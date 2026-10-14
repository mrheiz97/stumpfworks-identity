# PostgreSQL migration runbook

This runbook does not authorize a production cutover by itself. Use separate
migration and runtime credentials, keep secrets in root-readable files, and
retain SQLite until PostgreSQL acceptance is complete.

## Safety boundary

- Create and verify a fresh SQLite online backup before the maintenance window.
- Stop Identity writes before taking the migration snapshot. Copy the snapshot;
  never migrate directly from the live database file.
- Pre-create an empty PostgreSQL database/schema with migration credentials.
- Never pass a PostgreSQL URL on the command line. Use
  `--postgres-url-file` and mode `0600`.
- PostgreSQL TLS verification is the production default. `--allow-insecure` is
  limited to an isolated loopback rehearsal.
- Keep Badge/PIN, AD password fallback, PKINIT configuration and the previous
  Identity binary/configuration available for rollback.

## Local rehearsal

Use an isolated PostgreSQL instance and a synthetic SQLite snapshot. The tool
has three deliberately separate actions:

```text
identity-db-migrate \
  --postgres-url-file /root/identity-migration/postgres-url \
  --confirm create-empty-identity-schema \
  schema

identity-db-migrate \
  --postgres-url-file /root/identity-migration/postgres-url \
  --source /root/identity-migration/identity-snapshot.db \
  --max-rows 1000000 \
  --confirm import-stopped-snapshot \
  import

identity-db-migrate \
  --postgres-url-file /root/identity-migration/postgres-url \
  --source /root/identity-migration/identity-snapshot.db \
  --max-rows 1000000 \
  reconcile
```

`schema` refuses to adopt unverified existing application tables. `import`
requires an empty migrated target and is one transaction. `reconcile` compares
every normalized field while printing only per-table row counts. No record,
credential hash, subject, token, session identifier or comparison digest is
printed.

After reconciliation, create a custom-format `pg_dump`, restore it into another
empty rehearsal schema/database and reconcile the restored data with the same
SQLite snapshot. The automated PostgreSQL contract performs this sequence with
synthetic data.

## Production cutover gate

Before switching configuration, all of these must be true:

1. The SQLite snapshot passes `PRAGMA integrity_check`.
2. Schema creation and import completed without retrying an ambiguous failure.
3. Reconciliation reports `reconcile=verified`.
4. A PostgreSQL backup was restored into an empty target and verified.
5. Migration and runtime roles are separate; the runtime role cannot run DDL.
6. TLS hostname and CA verification work with the runtime URL.
7. The old SQLite database, previous configuration and binary are preserved.
8. A maintenance owner has recorded the exact rollback boundary below.

Switch `database.backend` and the protected PostgreSQL URL file only after these
checks. Start Identity and verify readiness, admin login, Access OIDC login,
OIDC client administration, Badge/PIN grant, PKINIT/TGT and the normal AD
password fallback before ending the maintenance window.

## Rollback and reconciliation boundary

Before PostgreSQL accepts any new application write, rollback is configuration
only: stop Identity, restore the previous SQLite configuration/binary, start it,
and repeat the authentication smoke tests.

After PostgreSQL accepts a new write, the old SQLite snapshot is stale. Do not
start it as a writable fallback. Stop Identity, preserve both databases, record
the failure time and reconcile/export the PostgreSQL changes under a reviewed
recovery plan. Automatic PostgreSQL-to-SQLite reverse migration is intentionally
not provided because silently dropping new audit, badge, client, session or OIDC
state would be unsafe.

## Evidence to retain

Retain timestamps and aggregate results only: snapshot integrity result,
per-table counts, reconciliation success, backup/restore success, tested build
hash, configuration backup location, rollback boundary and smoke-test results.
Do not place URLs with credentials, private keys, client secrets, PINs, badge
tokens, raw hashes or database rows in the change record.

## Production-snapshot rehearsal evidence

On 2026-10-14 an existing LOGIN01 online backup was copied into a temporary,
non-versioned local directory and rehearsed against an isolated PostgreSQL 17
cluster bound to loopback only. LOGIN01 remained active on SQLite and no
production configuration or data was changed.

- The source backup had mode `0600` and passed SQLite `integrity_check` in
  read-only mode.
- `identity-db-migrate` created an empty schema, imported all seven known
  application tables and reported `import=verified`.
- Reconciliation compared every normalized field, including preserved numeric
  IDs, credential hashes, OIDC subjects and audit history, and reported
  `reconcile=verified`.
- A custom-format `pg_dump` was restored into a second empty database. A second
  full reconciliation also reported `reconcile=verified`.
- `identity-admin` was exercised against the restored PostgreSQL database for
  OIDC client creation, secret rotation, disable and enable. Exactly four
  corresponding empty-detail audit events were verified. Generated test
  secrets were checked only in process memory and were not printed or stored.
- The isolated cluster was stopped afterward. The SQLite copy, PostgreSQL data,
  dump, restored database, logs, generated binary and temporary connection
  files were deleted completely.

This completes the production-snapshot rehearsal gate. It does not authorize a
production cutover. LOGIN01 remains on SQLite until a separately approved
maintenance window follows the cutover and rollback boundaries above.
