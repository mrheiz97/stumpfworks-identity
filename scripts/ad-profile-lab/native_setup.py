"""Compile/load only in the synthetic, networkless DC after earlier matrices."""
import json
import hashlib
import os
import pathlib
import subprocess

import ldb
import tdb
from samba import auth
from samba.samdb import SamDB
from samba.param import LoadParm

from broker_candidate import DB, fixture, loadparm, modify, one, sid


def setup(*, replica=False, fence=False, fixed=False):
    data = fixture()
    config = data["Config"]
    native_dir = pathlib.Path("/tmp/native-cas-dc2" if replica else "/tmp/native-cas")
    db = "/tmp/profile-replica/private/sam.ldb" if replica else DB
    module = "identity_native_create_dc2_lab" if replica else "identity_native_cas_lab"
    if fixed:
        if replica or protocol_for_fixed() is False:
            raise RuntimeError("fixed build requires an explicit single-DC Create fixture")
        module = "identity_fixed_create"
    lp = loadparm()
    if replica:
        from create_forest_research import invocation
        lp = LoadParm()
        lp.load("/tmp/profile-replica/etc/smb.conf")
    root = SamDB(url=db, lp=lp, session_info=auth.system_session(lp))
    if replica:
        config["DCIdentity"] = invocation(root).hex()
        config["URL"] = "ldaps://dc2.profile.test:636"
    if os.environ.get("IDENTITY_NATIVE_CREATE_LAB")=="1" and not replica:
        # Dedicated identity: no inherited profile WriteProperty delegation.
        # The shared random fixture password is laboratory-only, not a key design.
        root.newuser("creator",data["Password"],userou="OU=Outside")
        creator=one(root,"CN=creator,OU=Outside,"+config["BaseDN"])
        config["WriterDN"]=str(creator.dn)
        data["BrokerWriterGUID"]=bytes(creator["objectGUID"][0]).hex()
        data["BrokerWriterSID"]=sid(creator)
        root.newgroup("User Creators")
        root.newuser("profileonly",data["Password"],userou="OU=Outside")
        root.add_remove_group_members("Profile Operators",["profileonly"],add_members_operation=True)
        root.add_remove_group_members("Profile Operators",["operator"],add_members_operation=False)
        root.add_remove_group_members("User Creators",["operator"],add_members_operation=True)
        role=one(root,"CN=User Creators,CN=Users,"+config["BaseDN"])
        config["OperatorGroupDN"]=str(role.dn)
        config["OperatorGroupGUID"]=bytes(role["objectGUID"][0]).hex()
        pathlib.Path("/tmp/lab-config.json").write_text(json.dumps(data),encoding="utf-8")
    target = one(root, config["ManagedOU"], "(sAMAccountName=casprobe)", scope=ldb.SCOPE_ONELEVEL)
    writer = one(root, config["WriterDN"])
    actor = one(root, config["BaseDN"], "(sAMAccountName=operator)", scope=ldb.SCOPE_SUBTREE)
    # Samba permits unlocking with 0, but forbids deleting lockoutTime. Establish
    # an explicit reversible native-fixture baseline before any restriction test.
    for account in (writer, actor):
        if not account.get("lockoutTime"):
            modify(root, account.dn, {"lockoutTime": [b"0"]})
    domain = one(root, config["BaseDN"])
    os.umask(0o077)
    native_dir.mkdir(mode=0o700)
    private_key = str(native_dir / "issuer.pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", private_key], check=True)
    public = subprocess.check_output(["openssl", "pkey", "-in", private_key, "-pubout", "-outform", "DER"])
    if public[:12] != bytes.fromhex("302a300506032b6570032100") or len(public) != 44:
        raise RuntimeError("unexpected Ed25519 public key encoding")
    pins = {"PUBLIC_KEY": public[12:], "DOMAIN_GUID": bytes.fromhex(config["DomainGUID"]),
            "DC_GUID": bytes.fromhex(config["DCIdentity"]), "GROUP_GUID": bytes.fromhex(config["OperatorGroupGUID"])}
    for name, row in (("WRITER", writer), ("ACTOR", actor), ("TARGET", target), ("DOMAIN", domain)):
        pins[name + "_GUID"] = bytes(row["objectGUID"][0])
        pins[name + "_SID"] = bytes(row["objectSid"][0])
    protocol=int(os.environ.get("IDENTITY_NATIVE_PROTOCOL","1"))
    if protocol not in (1,2):raise RuntimeError("unsupported laboratory protocol")
    receipt_public=b""
    if protocol==2:
        receipt_key = str(native_dir / "receipt.pem")
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",receipt_key],check=True)
        receipt_der=subprocess.check_output(["openssl","pkey","-in",receipt_key,"-pubout","-outform","DER"])
        if len(receipt_der)!=44 or receipt_der[:12]!=public[:12]:raise RuntimeError("wrong receipt key")
        receipt_public=receipt_der[12:]
        pins["RECEIPT_PUBLIC_KEY"]=receipt_public
        pins["POLICY_HASH"]=hashlib.sha256(config["Revision"].encode("ascii")).digest()
        scope=b"".join(len(pins[k]).to_bytes(2,"big")+pins[k] for k in (
            "DOMAIN_SID","TARGET_SID","ACTOR_SID","WRITER_SID","DOMAIN_GUID","DC_GUID",
            "TARGET_GUID","ACTOR_GUID","WRITER_GUID","GROUP_GUID"))
        pins["SCOPE_HASH"]=hashlib.sha256(scope).digest()
    strings = {"BASE": config["BaseDN"], "MANAGED_OU": config["ManagedOU"], "WRITER_DN": str(writer.dn),
               "ACTOR_DN": str(actor.dn), "GROUP_DN": config["OperatorGroupDN"],
               "TARGET_FILTER": "(objectGUID=" + "".join("\\%02x" % b for b in pins["TARGET_GUID"]) + ")"}
    header = "/* Fresh synthetic pins, never supplied by requests. */\n"
    for key, value in pins.items():
        header += "static const uint8_t PIN_" + key + "[]={" + ",".join(str(b) for b in value) + "};\n"
    for key, value in strings.items():
        header += "#define PIN_" + key + " " + json.dumps(value) + "\n"
    header += f'#define NATIVE_DIR "{native_dir}"\n#define NATIVE_DB "{db}"\n#define NATIVE_MODULE "{module}"\n'
    (native_dir / "native_config.h").write_text(header, encoding="ascii")
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "ldb", "tdb", "talloc", "openssl"], text=True).split()
    protocol_flags=["-DIDENTITY_NATIVE_V2"] if protocol==2 else []
    if os.environ.get("IDENTITY_NATIVE_CREATE_LAB")=="1":
        if protocol!=2:raise RuntimeError("create fixture requires explicit protocol2")
        ou=one(root,config["ManagedOU"],attrs=["objectGUID","nTSecurityDescriptor"])
        from samba.dcerpc import security
        from samba.ndr import ndr_pack,ndr_unpack
        import uuid
        schema=one(root,root.get_schema_basedn(),"(lDAPDisplayName=user)",["schemaIDGUID"],ldb.SCOPE_SUBTREE)
        classguid=str(uuid.UUID(bytes_le=bytes(schema["schemaIDGUID"][0])))
        desc=ndr_unpack(security.descriptor,ou["nTSecurityDescriptor"][0])
        ace=security.descriptor.from_sddl("D:(OA;;CC;"+classguid+";;"+data["BrokerWriterSID"]+")",security.dom_sid(config["DomainSID"])).dacl.aces[0]
        if not replica:
            desc.dacl_add(ace);modify(root,ou.dn,{"nTSecurityDescriptor":[ndr_pack(desc)]})
        with (native_dir / "native_config.h").open("a",encoding="ascii") as f:
            f.write("static const uint8_t PIN_CREATE_OU_GUID[]={"+",".join(str(b) for b in bytes(ou["objectGUID"][0]))+"};\n")
        (native_dir / "create-ou").write_text(bytes(ou["objectGUID"][0]).hex(),encoding="ascii")
        protocol_flags.append("-DIDENTITY_NATIVE_CREATE")
        if fence:
            protocol_flags.append("-DIDENTITY_CREATE_FENCE")
    binary = str(native_dir / (module + ".so"))
    if fixed:
        from build_fixed_create_module import build, install
        pins["CREATE_OU_GUID"] = bytes(ou["objectGUID"][0])
        manifest = native_dir / "fixed-pins.json"
        manifest.write_text(json.dumps({
            **{name: value.hex() for name, value in pins.items() if name != "POLICY_HASH"},
            **{name: value for name, value in strings.items() if name != "TARGET_FILTER"},
            "NATIVE_DB": db, "NATIVE_DIR": str(native_dir), "CREATE_AUTHORITY": "/tmp/create-authority",
            "UPN_SUFFIX": "managed.profile.test", "REVISION": config["Revision"],
        }))
        build(manifest, pathlib.Path(binary))
        install(pathlib.Path(binary), pathlib.Path("/usr/lib/x86_64-linux-gnu/samba/ldb"))
    else:
        subprocess.run(["cc", "-std=c11", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-O2", "-g",
                    "-fsanitize=undefined", "-fno-sanitize-recover=all",
                    "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-Wl,-z,relro,-z,now", "-DIDENTITY_NATIVE_LAB_FAULTS",
                    "-I" + str(native_dir), str(pathlib.Path(__file__).with_name("native_cas.c")),
                        "-o", binary, *protocol_flags, *flags], check=True)
    journal = tdb.Tdb(str(native_dir / "journal.tdb"), 0, tdb.DEFAULT, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    journal.close()
    if not fixed:
        from install_native_create import install
        install(module)
    # Activation is separate from the file copy and only targets this fixture.
    raw = ldb.Ldb(db, options=["modules:"])
    row = raw.search(base="@MODULES", scope=ldb.SCOPE_BASE)[0]
    if list(row["@LIST"]) != [b"samba_dsdb"]:
        raise RuntimeError("unexpected synthetic module stack")
    msg = ldb.Message(); msg.dn = row.dn
    msg["@LIST"] = ldb.MessageElement([(module + ",samba_dsdb").encode()], ldb.FLAG_MOD_REPLACE, "@LIST")
    raw.modify(msg)
    (native_dir / "pins.json").write_text(json.dumps({"target_dn": str(target.dn), "actor_dn": str(actor.dn),
        "actor_guid": pins["ACTOR_GUID"].hex(), "writer_guid": pins["WRITER_GUID"].hex(),
        "actor_sid": pins["ACTOR_SID"].hex(),
        "target_guid": pins["TARGET_GUID"].hex(), "public": public.hex(),"protocol":protocol,
        "receipt_public":receipt_public.hex(),"scope":pins.get("SCOPE_HASH",b"").hex()}), encoding="ascii")
    if replica:
        (native_dir / "identity-fixture.json").write_text(json.dumps({"Config": config}), encoding="ascii")
    print("Native lab module built with warnings-as-errors; synthetic DSDB stack enabled", flush=True)


def protocol_for_fixed():
    return (os.environ.get("IDENTITY_CREATE_SYSTEMD_VM") == "1"
            and os.environ.get("IDENTITY_NATIVE_PROTOCOL") == "2"
            and os.environ.get("IDENTITY_NATIVE_CREATE_LAB") == "1")


if __name__ == "__main__":
    setup(fixed=os.environ.get("IDENTITY_CREATE_SYSTEMD_VM") == "1")
