#!/usr/bin/env python3
"""Create and verify a root-only PostgreSQL custom-format backup."""

from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("service_file", type=Path)
    parser.add_argument("backup_directory", type=Path)
    parser.add_argument("--retention-days", type=int, default=30)
    args = parser.parse_args()

    if args.retention_days < 1:
        parser.error("retention must be at least one day")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("backup must run as root")
    service = args.service_file.resolve(strict=True)
    service_stat = service.stat()
    if not stat.S_ISREG(service_stat.st_mode) or service_stat.st_uid != 0 or service_stat.st_mode & 0o077:
        raise RuntimeError("service file must be a regular root-only file")
    pg_dump = shutil.which("pg_dump")
    pg_restore = shutil.which("pg_restore")
    if not pg_dump or not pg_restore:
        raise RuntimeError("PostgreSQL client tools are unavailable")

    destination = args.backup_directory.resolve()
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(destination, 0o700)
    if destination.stat().st_uid != 0:
        raise RuntimeError("backup directory must be owned by root")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    final_path = destination / f"identity-{timestamp}.dump"
    environment = os.environ.copy()
    environment["PGSERVICEFILE"] = str(service)
    environment["PGCONNECT_TIMEOUT"] = "10"

    descriptor, temporary_name = tempfile.mkstemp(prefix=".identity-", suffix=".dump", dir=destination)
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        os.chmod(temporary_path, 0o600)
        subprocess.run(
            [pg_dump, "--format=custom", f"--file={temporary_path}", "service=identity_backup"],
            check=True,
            env=environment,
            stdin=subprocess.DEVNULL,
        )
        subprocess.run(
            [pg_restore, "--list", str(temporary_path)],
            check=True,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
        )
        temporary_path.replace(final_path)
    finally:
        temporary_path.unlink(missing_ok=True)

    cutoff = dt.datetime.now(dt.timezone.utc).timestamp() - args.retention_days * 86400
    for candidate in destination.glob("identity-*.dump"):
        if candidate != final_path and candidate.is_file() and candidate.stat().st_mtime < cutoff:
            candidate.unlink()
    print(f"backup={final_path.name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"backup failed: {error}", file=sys.stderr)
        raise SystemExit(1)
