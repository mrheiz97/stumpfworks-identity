"""Start the packaged executor as a dedicated UID against the installed module."""
import json
import os
from pathlib import Path
import subprocess
import time

from broker_candidate import fixture


def main():
    data = fixture()
    if os.geteuid() != 0:
        raise SystemExit("isolated root fixture required")
    uid = 65533
    state = Path("/tmp/fixed-create-service")
    runtime = Path("/tmp/fixed-create-socket")
    for directory, mode in ((state, 0o700), (runtime, 0o750)):
        directory.mkdir(mode=mode)
        directory.chmod(mode)
        os.chown(directory, uid, uid)
    native = Path("/tmp/native-cas")
    pins = json.loads((native / "pins.json").read_text())
    socket = runtime / "executor.sock"
    config = {
        "Directory": data["Config"],
        "Pins": {"ActorGUID": pins["actor_guid"], "ActorSID": pins["actor_sid"],
                 "WriterGUID": pins["writer_guid"], "ReceiptPublic": pins["receipt_public"],
                 "Scope": pins["scope"]},
        "OU": (native / "create-ou").read_text(),
        "Transport": {"Enabled": True, "Socket": str(socket),
                      "Owner": {"UID": uid, "GID": uid}, "Peer": {"UID": 65534, "GID": 65534}},
    }
    for name, value in {
        "config.json": json.dumps(config).encode(),
        "journal.key": os.urandom(32),
        "issuer.pem": (native / "issuer.pem").read_bytes(),
        "writer.password": Path(data["Config"]["PasswordFile"]).read_bytes(),
        "ca.pem": Path(data["Config"]["CAFile"]).read_bytes(),
    }.items():
        path = state / name
        path.write_bytes(value)
        os.chown(path, uid, uid)
    binary = ["/opt/stumpfworks-badge/create-executor", "-state", str(state)]
    identity = dict(user=uid, group=uid, extra_groups=[])
    subprocess.run(binary, check=True, **identity)
    assert not socket.exists() and not (state / "journal.db").exists()
    subprocess.run(binary + ["-initialize-journal"], check=True, **identity)
    process = subprocess.Popen(binary + ["-enable"], **identity)
    try:
        deadline = time.monotonic() + 15
        while not socket.is_socket():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("dedicated UID executor failed readiness")
            time.sleep(0.05)
        status = Path(f"/proc/{process.pid}/status").read_text()
        for label in ("Uid:", "Gid:"):
            assert next(line for line in status.splitlines() if line.startswith(label)).split()[1:] == [str(uid)] * 4
        assert socket.stat().st_uid == uid
    finally:
        process.terminate()
        assert process.wait(timeout=35) == 0
    assert (state / "journal.db").stat().st_uid == uid
    print("Installed native module and dedicated executor UID startup passed", flush=True)


if __name__ == "__main__":
    main()
