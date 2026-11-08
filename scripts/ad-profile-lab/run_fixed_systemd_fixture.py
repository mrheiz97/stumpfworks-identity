"""One fixed-module/systemd integration in a fresh disconnected guest."""
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import time

from broker_candidate import fixture
from verify_create_systemd import UNIT, check

HERE = Path(__file__).resolve().parent
STATE = Path("/var/lib/stumpfworks-badge-create")
RUNTIME = Path("/run/stumpfworks-badge-create")
MARKER = Path("/etc/stumpfworks-badge/ad-create-fixed.enabled")
AUTHORITY = Path("/tmp/create-authority")


def run(*args, **kwargs):
    subprocess.run(args, check=True, timeout=90, **kwargs)


def main():
    if (os.environ.get("IDENTITY_CREATE_SYSTEMD_VM") != "1" or os.geteuid() != 0
            or {name for _, name in socket.if_nameindex()} != {"lo"}
            or Path("/proc/1/comm").read_text().strip() != "systemd"
            or any(path.exists() for path in (STATE, RUNTIME, MARKER, AUTHORITY, Path("/tmp/profile-domain")))):
        raise SystemExit("requires a fresh disconnected systemd fixture")
    os.umask(0o077)
    os.environ.update(IDENTITY_AD_PROFILE_LAB="/tmp/lab-config.json",
                      IDENTITY_NATIVE_PROTOCOL="2", IDENTITY_NATIVE_CREATE_LAB="1")
    run("python3", "-B", str(HERE / "provision.py"))
    run("python3", "-B", str(HERE / "native_setup.py"))
    run("sh", str(HERE.parent / "install-ad-create-executor.sh"), sys.argv[1])
    data = fixture()
    native = Path("/tmp/native-cas")
    pins = json.loads((native / "pins.json").read_text())
    run("useradd", "--system", "--user-group", "--shell", "/usr/sbin/nologin", "swbadge-create")
    account = pwd.getpwnam("swbadge-create")
    uid, gid = account.pw_uid, account.pw_gid
    for path, mode in ((STATE, 0o700), (RUNTIME, 0o750)):
        path.mkdir()
        path.chmod(mode)
        os.chown(path, uid, gid)
    configuration = {
        "Directory": data["Config"],
        "Pins": {"ActorGUID": pins["actor_guid"], "ActorSID": pins["actor_sid"],
                 "WriterGUID": pins["writer_guid"], "ReceiptPublic": pins["receipt_public"],
                 "Scope": pins["scope"], "Epoch": 1, "FixedUPNSuffix": "managed.profile.test"},
        "OU": (native / "create-ou").read_text(),
        "Transport": {"Enabled": True, "Socket": str(RUNTIME / "executor.sock"),
                      "Owner": {"UID": uid, "GID": gid}, "Peer": {"UID": 65534, "GID": 65534}},
    }
    for name, value in {
        "config.json": json.dumps(configuration).encode(),
        "journal.key": os.urandom(32),
        "issuer.pem": (native / "issuer.pem").read_bytes(),
        "writer.password": Path(data["Config"]["PasswordFile"]).read_bytes(),
        "ca.pem": Path(data["Config"]["CAFile"]).read_bytes(),
    }.items():
        path = STATE / name
        path.write_bytes(value)
        os.chown(path, uid, gid)
    AUTHORITY.mkdir(mode=0o700)
    (AUTHORITY / "lock").touch()
    (AUTHORITY / "route").write_bytes((1).to_bytes(8, "big") + bytes.fromhex(data["Config"]["DCIdentity"]))
    run("/opt/stumpfworks-badge/create-executor", "-state", str(STATE), "-initialize-journal",
        user=uid, group=gid, extra_groups=[])
    run("systemctl", "daemon-reload")
    run("systemctl", "start", UNIT)
    assert subprocess.run(["systemctl", "is-active", "--quiet", UNIT], timeout=10).returncode != 0
    with open("/tmp/fixed-samba.log", "wb") as log:
        dc = subprocess.Popen(["samba", "-i", "-M", "single", "-s", "/tmp/profile-domain/etc/smb.conf"],
                              stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 20
        while True:
            if dc.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("fixed Samba did not open LDAPS; inspect /tmp/fixed-samba.log")
            try:
                with socket.create_connection(("127.0.0.1", 636), timeout=0.25):
                    break
            except OSError:
                time.sleep(0.25)
        MARKER.parent.mkdir(exist_ok=True)
        MARKER.touch(exist_ok=False)
        (AUTHORITY / "enabled").touch(exist_ok=False)
        run("systemctl", "start", UNIT)
        deadline = time.monotonic() + 15
        while not (RUNTIME / "executor.sock").is_socket():
            if time.monotonic() >= deadline:
                raise RuntimeError("executor socket readiness timeout")
            time.sleep(0.1)
        check()
    finally:
        (AUTHORITY / "enabled").unlink(missing_ok=True)
        MARKER.unlink(missing_ok=True)
        try:
            run("systemctl", "stop", UNIT)
        finally:
            dc.terminate()
            dc.wait(timeout=20)
    assert (STATE / "journal.db").is_file()


if __name__ == "__main__":
    main()
