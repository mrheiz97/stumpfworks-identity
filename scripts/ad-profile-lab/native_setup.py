"""Compile/load only in the synthetic, networkless DC after earlier matrices."""
import json
import os
import pathlib
import subprocess

import ldb
import tdb
from samba import auth
from samba.samdb import SamDB

from broker_candidate import DB, fixture, loadparm, modify, one


def setup():
    data = fixture()
    config = data["Config"]
    root = SamDB(url=DB, lp=loadparm(), session_info=auth.system_session(loadparm()))
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
    os.mkdir("/tmp/native-cas", 0o700)
    private_key = "/tmp/native-cas/issuer.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", private_key], check=True)
    public = subprocess.check_output(["openssl", "pkey", "-in", private_key, "-pubout", "-outform", "DER"])
    if public[:12] != bytes.fromhex("302a300506032b6570032100") or len(public) != 44:
        raise RuntimeError("unexpected Ed25519 public key encoding")
    pins = {"PUBLIC_KEY": public[12:], "DOMAIN_GUID": bytes.fromhex(config["DomainGUID"]),
            "DC_GUID": bytes.fromhex(config["DCIdentity"]), "GROUP_GUID": bytes.fromhex(config["OperatorGroupGUID"])}
    for name, row in (("WRITER", writer), ("ACTOR", actor), ("TARGET", target), ("DOMAIN", domain)):
        pins[name + "_GUID"] = bytes(row["objectGUID"][0])
        pins[name + "_SID"] = bytes(row["objectSid"][0])
    strings = {"BASE": config["BaseDN"], "MANAGED_OU": config["ManagedOU"], "WRITER_DN": str(writer.dn),
               "ACTOR_DN": str(actor.dn), "GROUP_DN": config["OperatorGroupDN"],
               "TARGET_FILTER": "(objectGUID=" + "".join("\\%02x" % b for b in pins["TARGET_GUID"]) + ")"}
    header = "/* Fresh synthetic pins, never supplied by requests. */\n"
    for key, value in pins.items():
        header += "static const uint8_t PIN_" + key + "[]={" + ",".join(str(b) for b in value) + "};\n"
    for key, value in strings.items():
        header += "#define PIN_" + key + " " + json.dumps(value) + "\n"
    pathlib.Path("/tmp/native-cas/native_config.h").write_text(header, encoding="ascii")
    flags = subprocess.check_output(["pkg-config", "--cflags", "--libs", "ldb", "tdb", "talloc", "openssl"], text=True).split()
    subprocess.run(["cc", "-std=c11", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-O2", "-g",
                    "-fsanitize=undefined", "-fno-sanitize-recover=all",
                    "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-Wl,-z,relro,-z,now", "-DIDENTITY_NATIVE_LAB_FAULTS",
                    "-I/tmp/native-cas", "/workspace/scripts/ad-profile-lab/native_cas.c",
                    "-o", "/tmp/native-cas/identity_native_cas_lab.so", *flags], check=True)
    journal = tdb.Tdb("/tmp/native-cas/journal.tdb", 0, tdb.DEFAULT, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    journal.close()
    # Link only in this disposable image, never a host Samba directory. Existing
    # core modules stay unchanged. @MODULES is a synthetic fixture mutation.
    module_dir = "/usr/lib/x86_64-linux-gnu/samba/ldb"
    if not os.path.isdir(module_dir):
        raise RuntimeError("review Samba module location")
    os.symlink("/tmp/native-cas/identity_native_cas_lab.so", module_dir + "/identity_native_cas_lab.so")
    raw = ldb.Ldb(DB, options=["modules:"])
    row = raw.search(base="@MODULES", scope=ldb.SCOPE_BASE)[0]
    if list(row["@LIST"]) != [b"samba_dsdb"]:
        raise RuntimeError("unexpected synthetic module stack")
    msg = ldb.Message(); msg.dn = row.dn
    msg["@LIST"] = ldb.MessageElement([b"identity_native_cas_lab,samba_dsdb"], ldb.FLAG_MOD_REPLACE, "@LIST")
    raw.modify(msg)
    pathlib.Path("/tmp/native-cas/pins.json").write_text(json.dumps({"target_dn": str(target.dn), "actor_dn": str(actor.dn),
        "actor_guid": pins["ACTOR_GUID"].hex(), "writer_guid": pins["WRITER_GUID"].hex(),
        "actor_sid": pins["ACTOR_SID"].hex(),
        "target_guid": pins["TARGET_GUID"].hex(), "public": public.hex()}), encoding="ascii")
    print("Native lab module built with warnings-as-errors; synthetic DSDB stack enabled", flush=True)


if __name__ == "__main__":
    setup()
