#!/usr/bin/env python3
"""Prepare local-only WYSE01 activation artifacts; never connect to a host."""
import base64
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist/wyse01-scheduled-updates-v1.13.0"
RELEASE = "37f928aa5774b18f661abcd580bf33d03322fd1d"
FINGERPRINT = "d94bd2573b017898d771913f358bff5386af5b300392bcc75ec02d8e42fec069"


def prepare():
    sources = {
        "client/sw-badge-client-update-worker": (
            "dist/releases/v1.13.0/linux-amd64/sw-badge-client-update-worker",
            "e0ca7b649f8c702c051eac0a25c1b8479d64e75f729f997c7305c429a5698492"),
        "verification-catalog/wyse01-v1130-status-updater.zip": (
            "dist/wyse01-v1.13.0/stumpfworks-client-1.13.0-status-updater-linux-amd64.zip",
            "b77d62b4e307010aa8e802851e53888d4a76e661af64a69b14bc2aa7d05045a0"),
    }
    # Validate all release inputs before writing any candidate files.
    checked = {}
    for destination, (source, expected) in sources.items():
        data = (ROOT / source).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"release input hash mismatch: {source}")
        checked[destination] = data
    public = (ROOT / "dist/wyse01-v1.13.0/stable-update-ed25519.pub").read_bytes()
    decoded = base64.b64decode(public.strip(), validate=True)
    if len(decoded) != 32 or hashlib.sha256(decoded).hexdigest() != FINGERPRINT:
        raise ValueError("stable public key fingerprint mismatch")
    checked.update({
        "client/client-update.pub": public,
        "server/update-stable.pub": public,
        "client/swbadge-client-updates.service": (ROOT / "deploy/systemd/swbadge-client-updates.service").read_bytes(),
        "client/swbadge-client-updates.timer": (ROOT / "deploy/systemd/swbadge-client-updates.timer").read_bytes(),
        "server/releases/approved.json": b"[]\n",
        "verification-catalog/approved.json": (json.dumps([{
            "id": "wyse01-v1130-status-updater",
            "sha256": sources["verification-catalog/wyse01-v1130-status-updater.zip"][1],
        }], indent=2) + "\n").encode(),
        "server/updates.yaml.fragment": b"updates:\n  catalog_directory: /var/lib/stumpfworks-badge-releases\n  public_key_file: /etc/stumpfworks-badge/update-stable.pub\n",
    })
    # Create-only output prevents silently overwriting a previously reviewed kit.
    OUTPUT.mkdir(parents=True, exist_ok=False)
    for destination, data in checked.items():
        path = OUTPUT / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(checked.items())}
    (OUTPUT / "SHA256SUMS").write_text("".join(f"{value}  {name}\n" for name, value in manifest.items()), encoding="utf-8")
    (OUTPUT / "PREPARATION.json").write_text(json.dumps({
        "release_commit": RELEASE, "worker_version": "1.13.0",
        "stable_decoded_key_sha256": FINGERPRINT,
        "production_modified": False, "timer_enabled": False,
        "activation_catalog_entries": 0,
        "verification_catalog_only": "already installed; never schedule on WYSE01",
        "excluded_client": "MOBILE01", "files": manifest,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Local preparation only: {OUTPUT}")


if __name__ == "__main__":
    prepare()
