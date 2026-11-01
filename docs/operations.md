# Operations Runbook

For client update scheduling, migration 7, worker bootstrap, maintenance gates
and rollback, see [scheduled client updates](client-update-jobs.md).

## Persistent WYSE VNC

Install `deploy/systemd/swbadge-vnc.service` and `scripts/swbadge-vnc-set-password.sh` as root. Run `/usr/local/sbin/swbadge-vnc-set-password` interactively once; never pass the VNC password as a command argument or store it in Git. Configure `SWBADGE_VNC_LISTEN` in `/etc/default/swbadge-vnc` for the client's trusted management interface. The safe template default is loopback only. The service requires `/etc/stumpfworks-badge/vnc.passwd` with mode `0600`, restarts after display-manager changes and is enabled at boot.

## Routine checks

LOGIN01:
```bash
systemctl is-active sw-badge-server.service
systemctl status swbadge-login01-maintenance.timer
systemctl show swbadge-login01-maintenance.service -p Result -p ExecMainStatus
journalctl -u swbadge-login01-maintenance.service --since today
```

DC01:
```bash
systemctl is-active samba-ad-dc.service
systemctl status swbadge-dc01-cert-check.timer
systemctl show swbadge-dc01-cert-check.service -p Result -p ExecMainStatus
samba-tool dbcheck --cross-ncs
```

FILE01:
```bash
systemctl is-active smbd winbind
wbinfo --ping-dc
wbinfo -t
net ads testjoin
```

WYSE01:
```bash
systemctl is-active lightdm
klist -c /tmp/krb5cc_$(id -u alice)
findmnt -t cifs
```

Create a privacy-limited diagnostic archive locally as root:

```bash
set -a
. /etc/stumpfworks-badge/client.conf
set +a
sw-badge-client-diagnostics --output /var/lib/stumpfworks-badge/diagnostics/manual.zip
```

The ZIP contains fixed readiness and service states only. It intentionally excludes IP addresses, SSIDs, usernames, logs, credentials, token contents, certificate contents and Kerberos principals. Review `diagnostics.json` before sharing the archive.

## Backup strategy

Use scheduled Proxmox backups for DC01 and LOGIN01, stored separately from guest disks. A snapshot is not a backup. LOGIN01 also creates daily online SQLite backups under `/var/backups/stumpfworks-badge`. The maintenance service uses Python's SQLite backup API and verifies the result before publishing it. Files are root-only. Because the database is small, v1.0 does not delete old backups automatically.

Before high-risk AD, PKINIT, PAM or deployment changes, confirm a recent Proxmox backup and create a change-specific rollback.

## SQLite restore

Restore only during a declared recovery window:

1. Select a backup and verify it with `PRAGMA integrity_check`.
2. Stop `sw-badge-server.service`.
3. Preserve the current database as a timestamped recovery copy.
4. Install the selected database as `/var/lib/stumpfworks-badge/badges.db`, owner `swbadge:swbadge`, mode `0640`.
5. Start the service and verify health, administrator login, self-service and badge login.

Do not restore SQLite to compensate for an AD problem. Do not casually roll back DC01 snapshots; use an AD-aware recovery plan.

## Certificate schedule

Verified on 23 August 2026:

- LOGIN01 HTTPS certificate: 24 November 2028
- DC01 KDC certificate: 24 November 2028
- Homelab TLS CA: 19 August 2036
- PKINIT CA: 19 August 2036

Daily timers fail 30 days before expiry. Renew certificates instead of disabling TLS validation.

## End-to-end acceptance

1. Badge and PIN login as the normal user.
2. Confirm a newly issued TGT and CIFS service ticket.
3. Confirm personal and public mounts use `sec=krb5` and correct `cruid`.
4. Test normal AD password fallback.
5. Test wrong PIN and revoked/expired credentials.
6. Confirm logs contain no secrets.

## Rollbacks

- LOGIN01 web/self-service: `/root/swbadge-web-selfservice-rollback-20260823-1100`
- LOGIN01 maintenance: `/root/swbadge-maintenance-rollback-20260823-1111`
- DC01 PKINIT: `/root/swbadge-pkinit-rollback`
- DC01 monitoring: `/root/swbadge-monitoring-rollback-20260823-1111`
- WYSE01 greeter and PAM rollback paths are recorded in `AGENTS.md`.
