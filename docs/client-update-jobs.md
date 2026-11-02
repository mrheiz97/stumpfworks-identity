# Scheduled client updates

WYSE01 deployment preparation (worker, empty Stable catalog, timer and recovery):
[local preparation and maintenance plan](releases/wyse01-scheduled-updates-preparation.md).
The already installed v1.13.0 is not a valid new scheduled update on that client.

The opt-in control plane adds the protected **Client updates** page and a
separate oneshot worker. Installation uses the existing signed verifier,
fixed targets, staging, health checks, automatic rollback and recovery.

## Approval and configuration

`clients.updates.write` is granted to administrators and client operators.
Auditors can inspect jobs through `clients.read`. Browser writes require
current directory roles and CSRF; unprotected/demo mode cannot mutate jobs.

The server accepts only stable Ed25519-signed Linux-amd64 packages in a local,
root-controlled catalog. The browser selects an approved ID, never commands,
URLs, paths or keys. Keep development and stable keys separate. Only the stable
public key belongs on server/client; private keys stay on the release workstation.

Use `update-packager` to sign a stable package and independently approve its
complete ZIP SHA-256. Put `<release-id>.zip` beside `approved.json`:

```json
[{"id":"stable-release-001","sha256":"<64 lowercase hexadecimal characters>"}]
```

IDs contain 16–64 ASCII letters, digits, underscores or hyphens. Startup verifies
signatures, payloads, components, architecture, channel and approval hash. Bytes
are frozen at startup; filesystem replacement cannot alter an active approval.
Invalid catalogs stop startup. Limits: 16 entries and 512 MiB total. Withdraw
approval by removing the entry and restarting through the approved deployment
workflow. Existing jobs keep their pinned hashes; already-started jobs can still
report results after withdrawal.

```yaml
updates:
  catalog_directory: /var/lib/stumpfworks-badge/releases
  public_key_file: /etc/stumpfworks-badge/update-stable.pub
```

Empty values disable execution. Environment equivalents are
`SWBADGE_UPDATE_CATALOG_DIRECTORY` and `SWBADGE_UPDATE_PUBLIC_KEY_FILE`.
Activation requires protected directory administration and the device API.

## Planning and lifecycle

Choose one enabled certificate-authenticated client and approved release.
Earliest/latest start use RFC 3339 with timezone; the page shows UTC. Windows
are at most 24 hours and may start up to 90 days ahead. Greeter packages require
explicit LightDM maintenance authorization for this job. That authorization does
not replace a separately approved production maintenance window.

| State | Meaning |
| --- | --- |
| scheduled | Waiting for client/window; cancelable |
| dispatched | Audited execution permission granted; awaiting result |
| succeeded | Installation and mandatory health checks passed |
| failed | Failed/interrupted; inspect rollback availability |
| cancelled | Cancelled before execution permission |
| expired | Did not start within the window |

Only one open job is allowed per client. Identical requests with the same request
ID are idempotent; conflicting reuse fails. Poll/download do not grant execution.
The start request atomically commits `scheduled` → `dispatched` with audit.
Concurrent cancellation/start has one winner. Offline clients start on reconnect
only within the window. Polling or scheduling a successor expires unstarted old
jobs; the UI also identifies expired jobs before reconnect. History shows 200 jobs.

Dispatched jobs are never automatically requeued. Lost replies do not prove
nonexecution. Late results are accepted; identical results are no-ops and conflicts
fail. Unreachable dispatched clients retain their open slot until reconciliation.
Restore connectivity and local evidence; do not clear jobs through SQL. Latest
start is not a completion guarantee. Safety recovery may restore services after
the window to preserve the previous working login.

## Device worker

The following POST routes exist only on the dedicated mTLS API:

| Suffix under `/api/v1/client/updates/` | Purpose |
| --- | --- |
| `poll` | This device's due/open job, or 204 |
| `{id}/package` | Exact approved package |
| `{id}/start` | Commit execution grant and audit |
| `{id}/result` | Commit bounded result and rollback availability |

URI-SAN, serial, fingerprint and active credential use the existing status
authentication contract. Certificate authentication is mandatory even in preferred
mode. Bearer tokens, disabled clients, revoked credentials and foreign devices
are rejected. These routes are absent from public and bootstrap listeners.

Build `cmd/client-update-worker` with the Makefile. Deployment units are
`swbadge-client-updates.service` and `.timer`. Polling is separate from status
because the updater starts the status service for mandatory health checks.
The guided installer does not automatically enable this new timer.
The existing root-controlled `client.conf` supplies:

```sh
SWBADGE_DEVICE_SERVER='https://identity.example.test:8444'
SWBADGE_CLIENT_ID='example-client'
SWBADGE_CA_FILE='/etc/stumpfworks-badge/server-ca.crt'
SWBADGE_DEVICE_BUNDLE_FILE='/etc/stumpfworks-badge/device/current.pem'
```

Stable public key: `/etc/stumpfworks-badge/client-update.pub`, overridable locally
with `--public-key`. No token is read. Redirects are rejected. ZIP hash, signature,
channel, architecture, release and minimum version are rechecked before execution.
Successful local update state prevents downgrades when the worker is unchanged.
The worker retains an independent `installed-version.json` so a later failed
attempt cannot erase the previous successfully installed version.

`/var/lib/stumpfworks-badge/update-jobs` is mode 0700; its mode-0600 `job.json`
is atomically written and synced before execution. Artifacts remain below each
job ID; rollback is `/var/backups/stumpfworks-badge/job-<id>`. Keep these through
acceptance. Never remove an open job's journal or rollback. Completed staging
artifacts may be removed under the normal retention policy.

An OS lock shared by guarded installation, worker and status recovery prevents
parallel mutations and is released on process death. Status reports skip recovery
while a live update holds the lock. On interruption the worker restores the
existing validated rollback and records failure before reporting. Its durable
journal also covers a missing updater marker after power loss. Invalid rollback
or incomplete recovery retains evidence and blocks execution. Lost acknowledgments
retry only the saved result. A dispatched job without local evidence is reported
conservatively as failed and never reinstalled. Results/audits contain no command
output, paths, logs or credentials.

## Migration, backup and rollout

PostgreSQL migration 7 adds `client_update_jobs` through the existing migration
account/tool; runtime retains no DDL privileges. SQLite adds the same table and
partial unique index on opening. Existing modes stay unchanged. The populated
table participates in import, binary-collated reconciliation and full dump/restore.
Preserve jobs and audit history together.

Production activation requires a new read-only preflight, stopped hash-verified
server/database/config rollback, verified client binaries/config/units rollback,
approved signed test artifact and explicit maintenance approval. Bootstrap the
updated updater (including shared lock) and worker together before enabling the
timer. Never enable the worker alongside an older unlocked updater. Enabling
polling itself does not require a greeter change or LightDM restart.

For rollback, stop/disable the worker timer and let the oneshot finish. Reconcile
dispatched jobs and complete pending recovery before downgrading. Restore verified
previous binaries, units and config. Server rollback uses a stopped consistent
binary/database snapshot; there is no destructive automated down-migration that
could discard execution evidence. Empty catalog configuration stops new grants
while retaining history and result acknowledgment.

Automated tests cover audit rollback, idempotency, concurrent start/cancel,
one-open-job enforcement, time boundaries, roles/CSRF, mTLS isolation, withdrawal,
tampering, lost responses, crash journals and locks. PostgreSQL runs the same
store contract and includes a populated job in import/reconciliation/real restore.
Hardware/production acceptance remains separate. Earlier login/certificate tests
are not claimed as newly repeated tests.
