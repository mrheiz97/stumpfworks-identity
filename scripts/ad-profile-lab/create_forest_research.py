"""Two actual writable Samba replicas in a disposable networkless container."""
from contextlib import contextmanager
import logging
import os
from pathlib import Path
import socket
import subprocess
import time

import ldb
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.join import join_DC
from samba.param import LoadParm
from samba.samdb import SamDB

HERE = Path(__file__).resolve().parent
ROOT = Path("/tmp/profile-domain/etc/smb.conf")
REPLICA = Path("/tmp/profile-replica/etc/smb.conf")
BASE = "DC=profile,DC=test"


@contextmanager
def running(config, address):
    with open(config.parent / "lab-samba.log", "wb") as log:
        process = subprocess.Popen(["samba", "-i", "-M", "single", "-s", str(config)],
                                   stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(120):
            if process.poll() is not None:
                raise RuntimeError((config.parent / "lab-samba.log").read_text())
            try:
                with socket.create_connection((address, 389), timeout=0.25):
                    break
            except OSError:
                time.sleep(0.25)
        else:
            raise RuntimeError(f"LDAP readiness timeout on {address}")
        yield
    finally:
        process.terminate()
        process.wait(timeout=15)


def config(path, address):
    run = path.parent / "run"
    run.mkdir()
    with path.open("a") as f:
        f.write(f"\n[global]\ninterfaces = {address}/8\nbind interfaces only = yes\n"
                f"pid directory = {run}\nncalrpc dir = {run}\nserver services = -dns -kcc -smb\n")


def find(db, attr, value):
    return db.search(base=BASE, expression=f"({attr}={value})",
                     attrs=["objectGUID", "userPrincipalName", "userAccountControl"])


def invocation(db):
    root = db.search(base="", scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])[0]
    return bytes(db.search(base=str(root["dsServiceName"][0]), scope=ldb.SCOPE_BASE,
                           attrs=["invocationId"])[0]["invocationId"][0])


def add(db, name, upn):
    db.add({"dn": f"CN={name},OU=Managed,{BASE}", "objectClass": "user",
            "sAMAccountName": name, "userPrincipalName": upn, "userAccountControl": "514"})


def main():
    if (os.environ.get("IDENTITY_CREATE_FOREST_LAB") != "1" or os.geteuid() != 0
            or {name for _, name in socket.if_nameindex()} != {"lo"}
            or ROOT.exists() or REPLICA.exists()):
        raise SystemExit("requires an explicit fresh root-owned networkless fixture")
    os.umask(0o077)
    subprocess.run(["python3", "-B", str(HERE / "provision.py")], check=True)
    config(ROOT, "127.0.0.1")
    with open("/etc/hosts", "a") as f:
        f.write("\n127.0.0.2 dc2.profile.test dc2\n")
    password = Path("/tmp/lab-password").read_text()
    creds = Credentials()
    creds.set_username("Administrator")
    creds.set_workstation("DC2")
    creds.set_password(password)
    creds.set_domain("PROFILE")
    creds.set_realm("PROFILE.TEST")
    creds.set_kerberos_state(DONT_USE_KERBEROS)
    with running(ROOT, "127.0.0.1"):
        lp = LoadParm()
        lp.load(str(ROOT))
        join_DC(logger=logging.getLogger("replica"), server="dc1.profile.test", creds=creds,
                lp=lp, netbios_name="DC2", targetdir=str(REPLICA.parent.parent),
                domain="profile.test", dns_backend="NONE")
        config(REPLICA, "127.0.0.2")
        with running(REPLICA, "127.0.0.2"):
            probe(lp, creds)
        replicate(REPLICA, "dc1")
    with running(REPLICA, "127.0.0.2"):
        check_duplicates(SamDB(url="ldap://dc2.profile.test", credentials=creds, lp=lp))
        replicate(ROOT, "dc2")
    with running(ROOT, "127.0.0.1"):
        check_duplicates(SamDB(url="ldap://dc1.profile.test", credentials=creds, lp=lp))
        check_duplicates(SamDB(url="ldap://dc1.profile.test:3268", credentials=creds, lp=lp))
    print("DRS replicated both disabled accounts with the same case-folded UPN", flush=True)


def replicate(destination, source):
    subprocess.run(["samba-tool", "drs", "replicate", "unused",
                    source + ".profile.test", BASE, "--local", "-s", str(destination),
                    "-P", "--use-kerberos=off"], check=True, timeout=60)


def probe(lp, creds):
    first = SamDB(url="ldap://dc1.profile.test", credentials=creds, lp=lp)
    second = SamDB(url="ldap://dc2.profile.test", credentials=creds, lp=lp)
    assert invocation(first) != invocation(second)
    assert first.get_domain_sid() == second.get_domain_sid()
    add(first, "ReplicaA", "replica-race@profile.test")
    assert len(find(first, "userPrincipalName", "REPLICA-RACE@PROFILE.TEST")) == 1
    assert not find(second, "userPrincipalName", "replica-race@profile.test")
    try:
        add(first, "LocalCollision", "REPLICA-RACE@PROFILE.TEST")
    except ldb.LdbError as exc:
        assert exc.args[0] == ldb.ERR_CONSTRAINT_VIOLATION
        print(f"same-DC case-insensitive duplicate rejected, LDAP {exc.args[0]}", flush=True)
    else:
        raise AssertionError("same-DC duplicate accepted")
    add(second, "ReplicaB", "REPLICA-RACE@PROFILE.TEST")
    assert not find(first, "sAMAccountName", "ReplicaB")
    print("both writable DCs accepted independently before replication", flush=True)


def check_duplicates(db):
    matches = find(db, "userPrincipalName", "replica-race@profile.test")
    assert len(matches) == 2
    assert len({bytes(row["objectGUID"][0]) for row in matches}) == 2
    assert all(str(row["userAccountControl"][0]) == "514" for row in matches)



if __name__ == "__main__":
    main()
