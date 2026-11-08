"""Read-only startup checks for the Create executor in a disposable systemd VM."""
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess

UNIT = "sw-badge-ad-create-fixed.service"
SOCKET = Path("/run/stumpfworks-badge-create/executor.sock")


def check():
    if (os.environ.get("IDENTITY_CREATE_SYSTEMD_VM") != "1" or os.geteuid() != 0
            or {name for _, name in socket.if_nameindex()} != {"lo"}
            or Path("/proc/1/comm").read_text().strip() != "systemd"):
        raise SystemExit("requires an explicit disconnected systemd fixture")
    properties = subprocess.check_output(
        ["systemctl", "show", UNIT, "-p", "ActiveState", "-p", "MainPID", "-p", "User"],
        text=True, timeout=10,
    )
    values = dict(line.split("=", 1) for line in properties.splitlines())
    if values.get("ActiveState") != "active" or values.get("User") != "swbadge-create":
        raise SystemExit("expected active executor service with dedicated user")
    pid = int(values["MainPID"])
    account = pwd.getpwnam("swbadge-create")
    if pid <= 1 or account.pw_uid == 0:
        raise SystemExit("unexpected executor process or root account")
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    for field, expected in (("Uid:", account.pw_uid), ("Gid:", account.pw_gid)):
        line = next(row for row in status if row.startswith(field))
        if [int(value) for value in line.split()[1:]] != [expected] * 4:
            raise SystemExit("executor process identity mismatch")
    endpoint = SOCKET.lstat()
    if (not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != account.pw_uid
            or stat.S_IMODE(endpoint.st_mode) != 0o660):
        raise SystemExit("executor socket ownership or permissions mismatch")
    print("Active systemd executor, dedicated UID/GID and socket verified")


if __name__ == "__main__":
    check()
