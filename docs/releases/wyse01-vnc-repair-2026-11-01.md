# WYSE01 VNC maintenance — 2026-11-01

Explicitly authorized VNC repair only. No client update/package/job, enrollment,
client-mode change, LOGIN01 change or MOBILE01 access/change was performed.
This record supersedes the VNC entry gate in the v1.13.0 client preparation;
it does not authorize that later client rollout.
That client rollout was subsequently approved and completed separately; see
the [status/updater acceptance](v1.13.0-wyse01-acceptance.md). This record
describes only the earlier VNC maintenance boundary.

## Two separate faults

1. x11vnc 0.9.17's extra IPv6 listener reported `listen6: bind: Address already
   in use`, although the intended service listened on one specific IPv4 address.
   This message alone did not prove a second rogue process. x11vnc and its
   LibVNCServer backend have separate IPv6 controls. `-no6` and `-noipv6` alone
   left the backend's wildcard IPv6 socket. Final configuration uses
   **`-no6 -rfbportv6 -1`**, verified against the actual socket set: exactly one
   listener on the previously configured IPv4 address, with no IPv6 listener.
   See [LibVNCServer's positive-port condition](https://github.com/LibVNC/libvncserver/blob/master/src/libvncserver/sockets.c).
2. The repeated process exits were caused by **XIO loss after display shutdown**,
   not the earlier nonfatal IPv6 warning. LightDM also restarted hundreds of
   times. Its greeter wrapper reported that `client.conf` was inaccessible:
   the file was correctly `root:lightdm 0640`, but the shared parent directory
   was `root:root 0700`. Effective access checks as `lightdm` confirmed failure.
   Restoring the client's documented directory contract, `root:lightdm 0750`,
   allowed the existing greeter to start and stopped the display/VNC cycle.

The installed VNC password helper contained an unconditional `install -d`
reset of this shared directory to `root:root 0700`. That is a proven defect
capable of producing this state; the historical invocation that changed the
directory was not independently established.

## Fresh rollback and exact changes

Before correction, a new mode-0700 recovery directory was created on WYSE01:
`/root/wyse01-vnc-rollback-20261101T175000Z`.

- Base SHA256SUMS: original VNC unit, x11vnc binary, protected password file,
  absence/ownership/mode metadata and service-state snapshot; six files checked.
- `SHA256SUMS.shared-parent`: original shared-directory metadata, captured
  immediately before restoring its owner/group/mode. Configuration contents
  were hashed privately and proved unchanged.
- `SHA256SUMS.vnc-helper`: original installed VNC password helper and its exact
  ownership/mode/hash, captured before replacing that helper.

All secret material remained on WYSE01 inside protected storage. The existing
VNC password was not reset or printed. Supplementary manifests preserve each
later recovery addition without rewriting the original verified manifest.

Production modifications were limited to:

- New VNC drop-in `swbadge-vnc.service.d/20-ipv4-listener.conf`, preserving the
  original command/address/authentication and adding the final IPv6 controls.
  Candidate units passed `systemd-analyze verify`; only VNC was explicitly
  restarted after daemon reload.
- Restored shared-directory metadata to the installer-defined
  `root:lightdm 0750`. No config-file content, account/group membership, PAM,
  LightDM configuration or greeter code was changed. No explicit LightDM restart
  was issued; its existing automatic restart recovered after access was repaired.
- Corrected existing `swbadge-vnc-set-password`: preserve existing real-directory
  ownership/mode, reject unsafe ownership/write access and symlink/non-directory
  paths, and create a new standalone
  directory privately when absent. Password output remains `root:root 0600`.
  The helper was syntax-checked, not executed against the real password.

The same fixes are retained in the repository unit template and helper. The
shared directory is traversable by the intended greeter group; VNC password,
status token and current/previous private device bundles remain individually
`root:root 0600` and unreadable by `lightdm`. Public config/CA access succeeds.

## Verification

The user confirmed the existing VNC connection shows the greeter and stays
stable. No user login/logout, forced disconnect, client update or authentication
mode change was used as a repair shortcut.

End-to-end helper tests use real Unix `install`/file permissions in isolated
temporary roots, with harmless replacements for password entry and systemctl:

- existing shared directory ownership/mode and config contents preserved;
- new directory private and new password root-only;
- symlink and regular-file paths rejected before side effects.
- non-root-owned or group-writable directories rejected without changing them.

All six pass against the fixed installed helper. The contract is committed as
`scripts/test-vnc-password-helper.py` and runs with isolated root fixtures in
Linux CI. The old helper is checked separately to ensure the regression is
actually detectable. No fixture calls the live VNC/password/systemd tools.

The final stability gate **passed** from 18:04:55 to 18:09:59 UTC: eleven
observations at 30-second intervals, unchanged LightDM/VNC/greeter process IDs
and restart counters, successful RFB banners, exactly one IPv4 listener, and
zero new IPv6 bind or XIO errors. VNC recorded zero automatic restarts after
the final controlled restart; LightDM's historical counter stayed at 802.
Client status/updater/device/greeter hashes remain at their pre-maintenance
versions; network/status timer stayed active and no pending update transaction
appeared. Earlier exploratory measurements were not passed off as this final
gate; the final run followed the last listener change. Results are root-only under
`/root/wyse01-vnc-change-20261101T175000Z/`.

## Recovery and boundary

Verify all three recovery manifests and saved metadata before recovery. To
undo only the listener change, remove this maintenance's new drop-in, reload
systemd and restart only VNC. The original base unit is unchanged. Restore the
saved helper atomically with its recorded owner/mode if necessary.

The saved **old shared-directory mode is known broken for the greeter**.
Restoring it would recreate the display failure; do not blindly apply all old
metadata as a "healthy" rollback. Retain the original record for exact recovery
and investigation, and select the recovery branch deliberately. Do not restore
an old password or change PAM/LightDM/client credentials merely to remove this
VNC drop-in. Preserve old recovery sets and the existing authentication mode.

This maintenance repairs VNC and its shared-directory interaction. The signed
v1.13.0 client packages remain local and uninstalled; their separate maintenance
approval, fresh full client snapshot and bootstrap checks are still required.
