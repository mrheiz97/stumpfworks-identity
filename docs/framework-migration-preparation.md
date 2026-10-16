# Framework integration and PostgreSQL preparation

Local preparation only. No production cutover or database driver change.

## Directory boundary

`internal/directory/lookup_overlay.go` provides `WithUserLookup`. It preserves
the existing authentication and listing implementation while allowing a
consumer callback to replace single-user reads. Tests verify lookup delegation,
unchanged auth policy, missing-user handling and propagated infrastructure
errors. `WithFrameworkUserLookup` bridges
the pinned framework LDAPS reader to Identity's user projection. Only missing
users map to `ErrUserNotFound`; ambiguity, outages and cancellation remain errors.
Tests cover projection, policy isolation, invalid results, rejected plaintext
configuration and cancellation before any network connection.
`LDAP.WithFrameworkLookups` derives read configuration from the same LDAP
instance, bounds custom CA files to 1 MiB, and rejects legacy certificate-pin
exceptions. Synthetic end-to-end TLS/BER LDAP tests cover full user projection,
missing/ambiguous users and untrusted certificates; ten shuffled runs passed.
The production LDAP certificate and trust path work, and a real framework LDAP
read was confirmed through the Access login. No silent certificate bypass or
automatic insecure fallback is allowed. Do not point read and auth adapters at
different directories.

The server has a separately controlled `directory.framework_read_enabled`
switch (environment: `SWBADGE_DIRECTORY_FRAMEWORK_READ_ENABLED`). When enabled,
only user reads use the framework adapter; password/admin authentication and
listing remain on the exact same LDAP configuration. Startup fails if the
legacy certificate-pin/SAN bypass is configured. The production CA, certificate
name and trust path are working, and the framework read path has been confirmed
through a real Access login. Runtime-selection tests still verify safe default
behavior, reject selection while the directory itself is disabled, reject the
legacy pin, and accept a normal CA/hostname-verifying configuration. On 2026-09-22 the complete local suite,
including disposable PostgreSQL import/restore and OIDC contracts, plus vet and
module verification passed. No production configuration was changed.

Identity now also has a default-off, bearer-protected `/metrics` endpoint using
the framework registry. Configuration uses `metrics.enabled` plus a runtime
`SWBADGE_METRICS_TOKEN` or root-readable `metrics.token_file`; tokens are not
accepted as command-line arguments or committed examples. HTTP metrics are
available immediately, and framework LDAP observations join them through the
enabled framework reader. Direct tests cover unauthorized and
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
The prepared CI workflow runs race tests against a synthetic PostgreSQL 16
service and explicitly requires matching dump/restore tools from the runner.
Disposable local PostgreSQL 17 tests cover the next major version. The workflow
has run successfully on GitHub against PostgreSQL 16 with the race detector.
Ten shuffled repetitions of directory/database/OIDC tests passed.

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

All eight table transfers, counts, synthetic subjects/hashes, ID sequences,
audit time/null preservation, FK/subject constraints, sequential code replay,
repeat execution and import-failure rollback passed locally on 2026-09-17.
This SQL-only tool is not application acceptance. Additional staged adapter
evidence is recorded below; full native badge/PKINIT flows and production
backup/cutover acceptance remain separate.

## Next implementation stages

The selectable `PostgresStore` reuses framework pool/transactions/migrations.
It covers users/PIN, OIDC subjects/client administration/codes, badges,
self-service sessions and greeter clients. Both the HTTP server and
`identity-admin` select the configured backend through one runtime opener; the
known production Identity instance remains on SQLite. Go 1.26.8 is now enforced; CI already
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

`ImportSQLite` accepts only an empty, migrated target and the known eight-table
source shape. It streams bounded rows, compares all normalized fields using
private digests, preserves numeric IDs/subjects/hashes/nulls and advances
sequences. It never writes source records. Limits: one million rows and two
minutes. UTC timestamps use PostgreSQL microseconds (sub-microsecond source
precision is truncated); naive SQLite timestamps mean UTC. Tests cover row
budget/unknown-column rejection and rollback when a target trigger alters a
copied field. A lost commit response is ambiguous: verify target state before
retry. Sequence gaps after failures are allowed. The guarded
`identity-db-migrate` CLI exposes schema creation, stopped-snapshot import and
aggregate-only reconciliation; it does not authorize a production cutover.
SQLite row/cell size is capped at 256 KiB and aggregate payload at 128 MiB. The
connection-local SQLite limit is restored after failures, never raised above
an existing stricter limit. Unknown tables and ASCII-fold duplicate accounts
are rejected. Locale-independent ASCII folding preserves SQLite lower()
semantics; non-ASCII case is not silently reinterpreted. Ambiguous PostgreSQL
lookups fail closed. Legacy clients.updated_at NULL values are retained.
Initial migrations refuse existing unverified application tables.
Generated or hidden source columns are refused. SQLite AUTOINCREMENT high-water
marks are retained, including IDs of deleted rows, and tested after restoration.

`WriteAudit` and `Counts` return errors, unlike legacy `Audit`/`Stats`. Both
backends now commit lost-badge revocation, replacement-badge activation,
successful badge last-use updates and OIDC code/token state with their canonical
audit events. Error-trigger tests prove rollback; competing lost-badge and OIDC
token requests produce exactly one winner and event. The HTTP server uses these
paths. PKINIT responses are also withheld unless their success event is durable.
User provisioning, PIN changes, web sessions and administrative badge changes
now use the same fail-closed policy. OIDC client administration and first
subject assignment through `identity-admin` also commit with audit and use the
configured SQLite/PostgreSQL backend. The guarded importer and full synthetic
database acceptance are complete; rehearsal with a protected production
snapshot and native production authentication acceptance remain separate
gates. A restricted temporary PostgreSQL login role can perform normal
operations but cannot create schema objects or run migrations. pg_dump/restore
of synthetic data preserves complete table fingerprints and ID sequences.
Actual Identity handlers pass PKCE, signature/subject, disabled-user, replay,
expiry, rate-limit and competing token-exchange tests against PostgreSQL. The
real framework login client passes trusted-local-TLS contracts with both
backends. Production credentials/TLS and native authentication remain
deployment gates. The HTTP server now depends on the shared
`database.ApplicationStore` contract,
which both SQLite and PostgreSQL satisfy at compile time. Runtime selection is
explicit and defaults to SQLite. PostgreSQL requires `database.backend:
postgres`, a protected URL file or `SWBADGE_POSTGRES_URL`, TLS by default, a
separately pre-migrated schema and sufficient runtime privileges. Startup checks
the schema using read-only aggregate queries and fails closed; it never runs DDL
with runtime credentials. Application-wide atomic success-audit coverage is
implemented. Synthetic backup/restore, migration-copy and reconciliation
acceptance are complete. A protected production-snapshot rehearsal, cutover
and post-cutover authentication acceptance remain open.

The original 1.26.0 build toolchain had reachable standard-library advisories;
`go run` had selected 1.26.8 for the scanner and masked the mismatch. Minimum
Go is now explicitly 1.26.8, and scan/build use that toolchain. Current scans
report no reachable/imported-package findings; one unimported OpenPGP module
advisory remains. LDAP/BER/NTLM, x/crypto and Windows x/sys dependencies were
updated locally. No patched binary or new adapter has been deployed.

1. Preserve numeric IDs and OIDC subjects, all credential hashes and history.
   Identity owns these tables; the framework supplies pool/migration primitives.
2. Review and approve the production procedure in
   `docs/postgresql-migration.md`, including maintenance ownership and runtime
   credentials.
3. Rehearse the documented procedure with a protected production snapshot
   before any production switch. Once PostgreSQL has
   accepted new writes, restoring an old SQLite snapshot would lose them; an
   explicit reconciliation strategy is required before promising rollback.
