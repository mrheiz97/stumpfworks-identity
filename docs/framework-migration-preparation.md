# Framework integration and PostgreSQL preparation

Local preparation only. No production cutover or database driver change.

## Directory boundary

`internal/directory/lookup_overlay.go` provides `WithUserLookup`. It preserves
the existing authentication and listing implementation while allowing a
consumer callback to replace single-user reads. Tests verify lookup delegation,
unchanged auth policy, missing-user handling and propagated infrastructure
errors. It is not wired into cmd/server. `WithFrameworkUserLookup` now bridges
the pinned framework LDAPS reader to Identity's user projection. Only missing
users map to `ErrUserNotFound`; ambiguity, outages and cancellation remain errors.
Tests cover projection, policy isolation, invalid results, rejected plaintext
configuration and cancellation before any network connection.
`LDAP.WithFrameworkLookups` derives read configuration from the same LDAP
instance, bounds custom CA files to 1 MiB, and rejects legacy certificate-pin
exceptions. Synthetic end-to-end TLS/BER LDAP tests cover full user projection,
missing/ambiguous users and untrusted certificates; ten shuffled runs passed.
Next: verified CA/SAN compatibility and explicit selection against an actual
directory. No silent certificate bypass or
automatic insecure fallback. Do not point read and auth adapters at different
directories.

The server now has a separate, default-off `directory.framework_read_enabled`
switch (environment: `SWBADGE_DIRECTORY_FRAMEWORK_READ_ENABLED`). When enabled,
only user reads use the framework adapter; password/admin authentication and
listing remain on the exact same LDAP configuration. Startup fails if the
legacy certificate-pin/SAN bypass is still configured. DC01 currently has no
DNS SAN, so this switch must remain disabled until its certificate is replaced.
The runtime-selection tests verify default-off behavior, reject selection while
the directory itself is disabled, reject the legacy pin, and accept a normal
CA/hostname-verifying configuration. On 2026-09-22 the complete local suite,
including disposable PostgreSQL import/restore and OIDC contracts, plus vet and
module verification passed. No production configuration was changed.

Identity now also has a default-off, bearer-protected `/metrics` endpoint using
the framework registry. Configuration uses `metrics.enabled` plus a runtime
`SWBADGE_METRICS_TOKEN` or root-readable `metrics.token_file`; tokens are not
accepted as command-line arguments or committed examples. HTTP metrics are
available immediately, and framework LDAP observations join them when that
separate adapter switch is later enabled. Direct tests cover unauthorized and
authorized scraping plus unchanged application routing. It is not deployed.

Prometheus should read the same token from a protected file rather than embed it
in its configuration. Example (replace target and paths locally):

```yaml
scrape_configs:
  - job_name: stumpfworks-identity
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/identity-metrics-token
    static_configs:
      - targets: ["login01.example.test:8080"]
```

Validate the complete configuration with `promtool check config` before reload.
The syntax follows Prometheus' documented `authorization.credentials_file` HTTP
client setting; the example contains no real hostname, token, or CA path.
An undeployed Linux/amd64 server build confirms Go 1.26.8 and the pinned
framework revision `84cdaec`; it is only a local build artifact.

On 2026-09-18 the full local Go 1.26.8 test suite, vet and module verification
passed, including synthetic PostgreSQL import/restore and OIDC contracts. The
Windows PKINIT certificate test requires OpenSSL on PATH; the installed Git
OpenSSL was used. No runtime adapter was enabled and no production data changed.
The prepared CI workflow runs race tests against a synthetic PostgreSQL 17
service and explicitly requires matching dump/restore tools. This workflow
change has not yet run on GitHub; local Windows checks do not establish race-test
acceptance. Ten shuffled repetitions of directory/database/OIDC tests passed.

## Synthetic PostgreSQL rehearsal

Use a disposable PostgreSQL 17 cluster only, listening on 127.0.0.1:55441.
Python's standard library and psql are required. The tool creates artificial
SQLite data in memory, never opens the configured Identity database, and wraps
its PostgreSQL schemas in transactions that are rolled back. This is not a
production importer. Schema translation is a prototype, not a supported store.

```powershell
$env:IDENTITY_REHEARSAL_ENABLED='1'
$env:IDENTITY_REHEARSAL_PSQL='C:\Program Files\PostgreSQL\17\bin\psql.exe'
python scripts/rehearse-postgres-synthetic.py
```

All seven table transfers, counts, synthetic subjects/hashes, ID sequences,
audit time/null preservation, FK/subject constraints, sequential code replay,
repeat execution and import-failure rollback passed locally on 2026-09-17.
This SQL-only tool is not application acceptance. Additional staged adapter
evidence is recorded below; full native badge/PKINIT flows and production
backup/cutover acceptance remain separate.

## Next implementation stages

The inactive `PostgresStore` now reuses framework pool/transactions/migrations.
It covers users/PIN, OIDC subjects/client administration/codes, badges,
self-service sessions and greeter clients. Both production entry points still
open SQLite. Go 1.26.8 is now enforced; CI already
reads the Go version from go.mod. Full local tests and vet passed after the bump.

Opt-in tests use a disposable database and unique schemas removed by cleanup:

```powershell
$env:IDENTITY_TEST_POSTGRES_URL='postgres://postgres@127.0.0.1:55441/postgres?sslmode=disable'
$env:IDENTITY_TEST_PG_DUMP='C:\Program Files\PostgreSQL\17\bin\pg_dump.exe'
$env:IDENTITY_TEST_PG_RESTORE='C:\Program Files\PostgreSQL\17\bin\pg_restore.exe'
go test ./internal/database ./internal/oidc -count=3
```

Shared contracts run against SQLite and PostgreSQL for PIN/client operations,
badge replacement/activation/revocation, session ownership/expiry/revocation,
greeter status/rotation and privacy-bounded audit reads. Concurrent subject
creation stays stable, codes have one winner, badge codes remain unique and
one original badge produces only one concurrent replacement.

`ImportSQLite` accepts only an empty, migrated target and the known seven-table
source shape. It streams bounded rows, compares all normalized fields using
private digests, preserves numeric IDs/subjects/hashes/nulls and advances
sequences. It never writes source records. Limits: one million rows and two
minutes. UTC timestamps use PostgreSQL microseconds (sub-microsecond source
precision is truncated); naive SQLite timestamps mean UTC. Tests cover row
budget/unknown-column rejection and rollback when a target trigger alters a
copied field. A lost commit response is ambiguous: verify target state before
retry. Sequence gaps after failures are allowed. No production CLI is exposed.
SQLite row/cell size is capped at 256 KiB and aggregate payload at 128 MiB. The
connection-local SQLite limit is restored after failures, never raised above
an existing stricter limit. Unknown tables and ASCII-fold duplicate accounts
are rejected. Locale-independent ASCII folding preserves SQLite lower()
semantics; non-ASCII case is not silently reinterpreted. Ambiguous PostgreSQL
lookups fail closed. Legacy clients.updated_at NULL values are retained.
Initial migrations refuse existing unverified application tables.
Generated or hidden source columns are refused. SQLite AUTOINCREMENT high-water
marks are retained, including IDs of deleted rows, and tested after restoration.

`WriteAudit` and `Counts` return errors, unlike legacy `Audit`/`Stats`; application
failure policy remains separate open work. Both backends now expose a staged
`RevokeActiveBadgeForUserWithAudit`: mutation and canonical lost-badge audit
commit together or roll back together. Error-trigger tests keep the badge active;
eight competitors produce exactly one revocation and one event. Existing server
callers still use their old path; this API is not enabled in production.
This is not a drop-in Store replacement, production-ready importer or full auth
acceptance. A restricted temporary PostgreSQL login role can perform normal
operations but cannot create schema objects or run migrations. pg_dump/restore
of synthetic data preserves complete table fingerprints and ID sequences.
Actual Identity handlers pass PKCE, signature/subject, disabled-user, replay,
expiry, rate-limit and competing token-exchange tests against PostgreSQL. The
real framework login client passes trusted-local-TLS contracts with both
backends. Production credentials/TLS, backup/restore, native authentication,
application-wide audit policy and startup/interface integration remain open.

The original 1.26.0 build toolchain had reachable standard-library advisories;
`go run` had selected 1.26.8 for the scanner and masked the mismatch. Minimum
Go is now explicitly 1.26.8, and scan/build use that toolchain. Current scans
report no reachable/imported-package findings; one unimported OpenPGP module
advisory remains. LDAP/BER/NTLM, x/crypto and Windows x/sys dependencies were
updated locally. No patched binary or new adapter has been deployed.

1. Inventory Store queries and both cmd/server and cmd/identity-admin startup.
   Move question-mark placeholders, bool comparisons, LastInsertId and SQLite
   schema introspection to explicit PostgreSQL implementations.
2. Preserve numeric IDs and OIDC subjects, all credential hashes and history.
   Identity owns these tables; the framework supplies pool/migration primitives.
3. Rewrite code consumption as one atomic UPDATE ... RETURNING with client,
   callback and expiry constraints; test competing consumers and rollback.
4. Make audit errors visible and test mutation-plus-audit atomicity (the current
   Store Audit method ignores errors). Treat this as a separate behavior change.
5. Build a bounded importer and verify every table with aggregate-safe output.
6. Rehearse backup/restore before any production switch. Once PostgreSQL has
   accepted new writes, restoring an old SQLite snapshot would lose them; an
   explicit reconciliation strategy is required before promising rollback.
