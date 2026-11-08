"""Install one fixture-specific LDB module without changing the DSDB stack."""
import os
from pathlib import Path
import shutil
import socket

MODULE_DIR = Path("/usr/lib/x86_64-linux-gnu/samba/ldb")
SOURCES = {
    "identity_native_cas_lab": Path("/tmp/native-cas"),
    "identity_native_create_dc2_lab": Path("/tmp/native-cas-dc2"),
}


def install(module):
    if (os.geteuid() != 0 or os.environ.get("IDENTITY_AD_PROFILE_LAB") != "/tmp/lab-config.json"
            or {name for _, name in socket.if_nameindex()} != {"lo"}
            or not Path("/tmp/lab-config.json").is_file()):
        raise RuntimeError("installation requires a disposable networkless Samba fixture")
    source = SOURCES[module] / (module + ".so")
    target = MODULE_DIR / source.name
    with source.open("rb") as src:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            with os.fdopen(fd, "wb") as output:
                shutil.copyfileobj(src, output)
                output.flush()
                os.fchmod(output.fileno(), 0o644)
                os.fsync(output.fileno())
        except BaseException:
            target.unlink()
            raise
    return target


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", choices=tuple(SOURCES))
    print(install(parser.parse_args().module))
