"""Native two-DC handoff fixture, with one root-owned authority on one host."""
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import socket
import subprocess
import tempfile

import ldb
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba.join import join_DC
from samba.samdb import SamDB

from broker_candidate import fixture, loadparm
from create_forest_research import HERE, ROOT, REPLICA, BASE, add, config, find, invocation, replicate, running
from create_research import packet, send, status
from native_setup import setup

AUTHORITY = Path("/tmp/create-authority")
SUFFIX = "@managed.profile.test"


def route(epoch, dc):
    return epoch.to_bytes(8, "big") + dc


def change_route(old, new, *, reservations=None):
    with (AUTHORITY / "lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (AUTHORITY / "route").read_bytes() != old:
            raise RuntimeError("unexpected route")
        if reservations is not None:
            expected = {AUTHORITY / ("upn-" + name): digest for name, digest in reservations.items()}
            if set(AUTHORITY.glob("upn-*")) != set(expected):
                raise RuntimeError("unaccounted reservations")
            if any(path.read_bytes() != digest for path, digest in expected.items()):
                raise RuntimeError("reservation differs from authenticated receipt")
        with tempfile.NamedTemporaryFile(dir=AUTHORITY, delete=False) as file:
            staged = Path(file.name)
            try:
                file.write(new)
                file.flush()
                os.fsync(file.fileno())
                staged.replace(AUTHORITY / "route")
                directory = os.open(AUTHORITY, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                staged.unlink(missing_ok=True)


def connect(host, username):
    data = fixture()
    creds = Credentials()
    creds.set_bind_dn(data["Config"]["WriterDN"] if username == "creator"
                      else "CN=Administrator,CN=Users," + BASE)
    creds.set_password(data["Password"])
    creds.set_kerberos_state(DONT_USE_KERBEROS)
    return SamDB(url=f"ldaps://{host}.profile.test", credentials=creds, lp=loadparm())


def denied(call, *args):
    try:
        call(*args)
    except ldb.LdbError as exc:
        assert exc.args[0] == ldb.ERR_UNWILLING_TO_PERFORM, exc
    else:
        raise AssertionError("unfenced write succeeded")


def raw_paths(db):
    denied(add, db, "bypass", "Bypass" + SUFFIX.upper())
    msg = ldb.Message()
    msg.dn = ldb.Dn(db, "CN=ordinary,OU=Managed," + BASE)
    for attr in ("userPrincipalName", "1.2.840.113556.1.4.656"):
        msg[attr] = ldb.MessageElement(["Bypass" + SUFFIX], ldb.FLAG_MOD_REPLACE, attr)
        denied(db.modify, msg)
        del msg[attr]

def journal_phase(phase):
    if os.environ.get("IDENTITY_CREATE_V2_LAB") == "1":
        env = dict(os.environ, IDENTITY_CREATE_JOURNAL_PHASE=phase)
        subprocess.run(["/tests/adprofile.test", "-test.v", "-test.run",
                        "^TestCreateJournalHandoffLab$"], env=env, check=True, timeout=60)


def main():
    if (os.environ.get("IDENTITY_CREATE_FENCE_LAB") != "1" or os.geteuid() != 0
            or {name for _, name in socket.if_nameindex()} != {"lo"}
            or ROOT.exists() or REPLICA.exists() or AUTHORITY.exists()):
        raise SystemExit("requires an explicit fresh networkless root fixture")
    os.umask(0o077)
    os.environ.update(IDENTITY_AD_PROFILE_LAB="/tmp/lab-config.json",
                      IDENTITY_NATIVE_PROTOCOL="2", IDENTITY_NATIVE_CREATE_LAB="1",
                      UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    subprocess.run(["python3", "-B", str(HERE / "provision.py")], check=True)
    config(ROOT, "127.0.0.1")
    with open("/etc/hosts", "a") as hosts:
        hosts.write("\n127.0.0.2 dc2.profile.test dc2\n")
    setup(fence=True)
    creds = Credentials()
    creds.set_username("Administrator")
    creds.set_workstation("DC2")
    creds.set_password(fixture()["Password"])
    creds.set_domain("PROFILE")
    creds.set_realm("PROFILE.TEST")
    creds.set_kerberos_state(DONT_USE_KERBEROS)
    AUTHORITY.mkdir()
    old = bytes.fromhex(fixture()["Config"]["DCIdentity"])
    (AUTHORITY / "lock").touch(exist_ok=False)
    (AUTHORITY / "route").write_bytes(route(1, old))
    with running(ROOT, "127.0.0.1"):
        join_DC(logger=logging.getLogger("replica"), server="dc1.profile.test", creds=creds,
                lp=loadparm(), netbios_name="DC2", targetdir=str(REPLICA.parent.parent),
                domain="profile.test", dns_backend="NONE")
        config(REPLICA, "127.0.0.2")
        with REPLICA.open("a") as conf:
            conf.write("\ntls enabled = yes\ntls keyfile = /tmp/dc.key\n"
                       "tls certfile = /tmp/dc.pem\ntls cafile = /tmp/ca.pem\n")
        setup(replica=True, fence=True)
        result = exercise(old)
    if result is not None:
        return_to_first(old, *result)
    for config_path in (ROOT, REPLICA):
        log = (config_path.parent / "lab-samba.log").read_text()
        assert "runtime error:" not in log and "UndefinedBehaviorSanitizer" not in log


def exercise(old):
    first = connect("dc1", "creator")
    journal_phase("before")
    admin = connect("dc1", "Administrator")
    raw_paths(admin)
    original = packet("handed", epoch=1)
    delayed = packet("delayed", epoch=1)
    denied(send, first, "handed", packet("handed"))
    with (AUTHORITY / "lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        denied(send, first, "handed", original)
    assert not list(AUTHORITY.glob("upn-*"))
    with running(REPLICA, "127.0.0.2"):
        second = connect("dc2", "creator")
        new = invocation(second)
        assert new != old
        key = Path("/tmp/native-cas-dc2/issuer.pem")
        def on_second(name, epoch):
            return packet(name, epoch=epoch, key=key, dc=new)

        raw_paths(connect("dc2", "Administrator"))
        denied(send, second, "early", on_second("early", 1))
        send(first, "handed", original)
        assert not find(second, "userPrincipalName", "handed" + SUFFIX)

    frozen = route(1, bytes(16))
    change_route(route(1, old), frozen)
    denied(send, first, "delayed", delayed)
    receipt = status(first, original)
    assert receipt[256] == 2
    digest = hashlib.sha256(original[:-64]).digest()
    replicate(REPLICA, "dc1")
    with running(REPLICA, "127.0.0.2"):
        second = connect("dc2", "creator")
        assert invocation(second) == new
        rows = find(second, "userPrincipalName", "HANDED" + SUFFIX.upper())
        assert len(rows) == 1 and bytes(rows[0]["objectGUID"][0]) == receipt[265:281]
        assert str(rows[0]["userAccountControl"][0]) == "514"
        try:
            change_route(frozen, route(2, new), reservations={"handed": bytes(32)})
        except RuntimeError as exc:
            assert str(exc) == "reservation differs from authenticated receipt"
        else:
            raise AssertionError("promotion accepted inconsistent evidence")
        denied(send, second, "fresh", on_second("fresh", 2))
        change_route(frozen, route(2, new), reservations={"handed": digest})
        denied(send, first, "delayed", delayed)
        denied(send, second, "fresh", on_second("fresh", 1))
        denied(send, second, "handed", on_second("handed", 2))
        denied(send, second, "Handed", on_second("Handed", 2))
        fresh = on_second("fresh", 2)
        send(second, "fresh", fresh)
        assert len(find(second, "userPrincipalName", "fresh" + SUFFIX)) == 1
        assert not find(first, "userPrincipalName", "delayed" + SUFFIX)
        if os.environ.get("IDENTITY_CREATE_V2_LAB") == "1":
            journal_phase("after")
            if os.environ.get("IDENTITY_CREATE_RETURN_LAB") == "1":
                fresh_receipt = status(second, fresh, native_dir=key.parent)
                assert fresh_receipt[256] == 2
                proof = json.loads(Path("/tmp/identity-handoff-executor/dc2-evidence.json").read_text())
                evidence = {
                    "handed": (digest, receipt[265:281]),
                    "fresh": (hashlib.sha256(fresh[:-64]).digest(), fresh_receipt[265:281]),
                    "handoffnext": (bytes.fromhex(proof["digest"]), bytes.fromhex(proof["guid"])),
                }
                assert not find(first, "userPrincipalName", "handoffnext" + SUFFIX)
                change_route(route(2, new), route(2, bytes(16)))
                return new, evidence
            subprocess.run(["/tests/adprofile.test", "-test.v", "-test.run",
                            "^Test(CreateExecutorProcess|CreateIdentityLab)$"], check=True, timeout=90)
        print("native handoff passed: authenticated receipt, DRS object identity, stale denial, new Add",
              flush=True)

def return_to_first(old, new, evidence):
    with running(REPLICA, "127.0.0.2"):
        second = connect("dc2", "creator")
        delayed = packet("returnlate", epoch=2, key=Path("/tmp/native-cas-dc2/issuer.pem"), dc=new)
        denied(send, second, "returnlate", delayed)
        replicate(ROOT, "dc2")
        with running(ROOT, "127.0.0.1"):
            first = connect("dc1", "creator")
            assert invocation(first) == old
            for name, (_, guid) in evidence.items():
                rows = find(first, "userPrincipalName", name + SUFFIX)
                assert len(rows) == 1 and bytes(rows[0]["objectGUID"][0]) == guid
                assert str(rows[0]["userAccountControl"][0]) == "514"
            change_route(route(2, bytes(16)), route(3, old),
                         reservations={name: digest for name, (digest, _) in evidence.items()})
            denied(send, second, "returnlate", delayed)
            denied(send, first, "returnstale", packet("returnstale", epoch=1))
            denied(send, first, "fresh", packet("fresh", epoch=3))
            journal_phase("return")
            assert len(find(first, "userPrincipalName", "returnnext" + SUFFIX)) == 1
            print("native return passed: DC1 -> DC2 -> DC1, epoch 3, original Identity journal", flush=True)


if __name__ == "__main__":
    main()
