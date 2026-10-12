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
