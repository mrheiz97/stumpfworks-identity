"""Build a fixed-DC Create module against the target Samba development ABI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile

MODULE = "identity_fixed_create"
GUIDS = ("DOMAIN_GUID", "DC_GUID", "GROUP_GUID", "WRITER_GUID", "ACTOR_GUID",
         "TARGET_GUID", "CREATE_OU_GUID")
SIDS = ("DOMAIN_SID", "WRITER_SID", "ACTOR_SID", "TARGET_SID")
KEYS = ("PUBLIC_KEY", "RECEIPT_PUBLIC_KEY", "SCOPE_HASH")
DNS = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")


def load_header(manifest):
    data = json.loads(manifest.read_text())
    strings = ("BASE", "MANAGED_OU", "WRITER_DN", "ACTOR_DN", "GROUP_DN",
               "NATIVE_DB", "NATIVE_DIR", "CREATE_AUTHORITY", "UPN_SUFFIX", "REVISION")
    if set(data) != set(GUIDS + SIDS + KEYS + strings):
        raise ValueError("manifest must contain exactly the documented fields")
    if any(not re.fullmatch(r"[ -~]{1,512}", data[name]) for name in strings):
        raise ValueError("invalid manifest text")
    for name in ("NATIVE_DB", "NATIVE_DIR", "CREATE_AUTHORITY"):
        path = Path(data[name])
        if not path.is_absolute() or path == Path("/") or ".." in path.parts or str(path) != data[name]:
            raise ValueError("native paths must be canonical absolute paths")
    if len(data["UPN_SUFFIX"]) > 253 or not DNS.fullmatch(data["UPN_SUFFIX"]):
        raise ValueError("invalid fixed UPN suffix")
    pins = {}
    for name in GUIDS + SIDS + KEYS:
        if not re.fullmatch(r"[0-9a-f]+", data[name]):
            raise ValueError(f"invalid raw hex for {name}")
        value = bytes.fromhex(data[name])
        if (not any(value) or
                (name in GUIDS and len(value) != 16) or
                (name in KEYS and len(value) != 32) or
                (name in SIDS and (len(value) < 8 or value[0] != 1 or
                                   not 1 <= value[1] <= 15 or len(value) != 8 + 4 * value[1]))):
            raise ValueError(f"invalid raw pin size for {name}")
        pins[name] = value
    if pins["PUBLIC_KEY"] == pins["RECEIPT_PUBLIC_KEY"]:
        raise ValueError("issuer and receipt keys must differ")
    pins["POLICY_HASH"] = hashlib.sha256((data["REVISION"] + "\x00" + data["UPN_SUFFIX"]).encode()).digest()
    defines = {f"PIN_{name}": data[name] for name in strings[:5]}
    defines["PIN_TARGET_FILTER"] = "(objectGUID=" + "".join(f"\\{byte:02x}" for byte in pins["TARGET_GUID"]) + ")"
    defines.update({name: data[name] for name in strings[5:8]})
    defines.update(NATIVE_MODULE=MODULE, CREATE_UPN_SUFFIX="@" + data["UPN_SUFFIX"])
    lines = [f"#define {name} {json.dumps(value)}" for name, value in defines.items()]
    lines.extend(f"static const uint8_t PIN_{name}[]={{{','.join(map(str, value))}}};"
                 for name, value in pins.items())
    return "\n".join(lines) + "\n"


def build(manifest, output):
    if output.name != MODULE + ".so":
        raise ValueError("output must be named identity_fixed_create.so")
    source = Path(__file__).resolve().with_name("native_cas.c")
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "ldb", "tdb", "talloc", "openssl"], text=True))
    header = load_header(manifest)
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        directory = Path(temp)
        (directory / "native_config.h").write_text(header, encoding="ascii")
        artifact = directory / output.name
        subprocess.run(["cc", "-std=c11", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                        "-O2", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2",
                        "-Wl,-z,relro,-z,now", "-DIDENTITY_NATIVE_V2", "-DIDENTITY_NATIVE_CREATE",
                        "-DIDENTITY_CREATE_FENCE", "-DIDENTITY_FIXED_CREATE_DC",
                        "-I" + str(directory), str(source), "-o", str(artifact), *flags], check=True)
        os.link(artifact, output)

def install(artifact, module_dir):
    info = module_dir.lstat()
    if (os.geteuid() != 0 or not module_dir.is_absolute() or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_mode & 0o022):
        raise ValueError("Samba module directory must be absolute and root-owned")
    with tempfile.NamedTemporaryFile(dir=module_dir) as staging:
        with artifact.open("rb") as source:
            shutil.copyfileobj(source, staging)
        staging.flush()
        os.fchmod(staging.fileno(), 0o644)
        os.fsync(staging.fileno())
        os.link(staging.name, module_dir / artifact.name)
    fd = os.open(module_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--install-dir", type=Path, help="install into the exact target Samba LDB module directory")
    args = parser.parse_args()
    build(args.manifest, args.output)
    if args.install_dir is not None:
        install(args.output, args.install_dir)
