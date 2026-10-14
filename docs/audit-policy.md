# Audit failure policy

Identity separates security decisions from their audit evidence. Audit records
must never contain passwords, PINs, badge tokens, client secrets or raw database
errors.

## Required behaviour

| Event class | Audit failure behaviour |
|---|---|
| Rejected authentication or authorization | Keep the request rejected, emit a bounded operational error, and never reveal the audit failure to the caller. |
| Successful credential or token issuance | Do not report success unless the required audit record is durable. New flows must implement this before production use. |
| Security-sensitive state mutation | Commit the mutation and success audit in one database transaction, or commit neither. |
| Informational or availability event | Best effort is allowed, but a bounded operational error must make loss visible. |

Retries must not duplicate a successful mutation or make a one-use credential
reusable. Database errors are sensitive and are not logged verbatim.

## Current enforcement

- SQLite and PostgreSQL expose error-returning audit writes.
- Audit write failures emit only the fixed component and bounded event type.
- Self-service lost-badge revocation and replacement-badge activation are
  atomic with their success events on both backends; audit failure leaves the
  previous badge state unchanged.
- Successful badge authentication updates the badge last-use marker and writes
  `auth_success` in one transaction on both backends. A login grant is retained
  in memory and returned only after that transaction commits.
- PKINIT certificates are returned only after `pkinit_issued` is durable. An
  audit failure returns an availability error, exposes no certificate and does
  not make the consumed one-time grant reusable.
- OIDC authorization codes commit with their login, consent and code-issued
  events. Token exchange reads and validates without consuming, prepares token
  material privately, then commits code consumption with `oidc_token_issued`.
  Audit failure exposes neither code nor token material; concurrent exchanges
  still have exactly one winner.
- First-login OIDC user provisioning and stable subject assignment are each
  transactionally audited before authorization continues.
- Administrator login is accepted and cookie material is created only after
  its success event is durable.
- User provisioning, PIN changes, self-service session creation/revocation and
  administrative badge creation/revocation/replacement commit with their
  success events on both backends.
- The `identity-admin` OIDC client create, secret rotation, enable/disable and
  first subject assignment operations use the configured runtime backend and
  commit their mutation with the corresponding audit event. One-time client
  secrets are printed only after the transaction commits. End-to-end command
  contracts exercise this behavior on both SQLite and PostgreSQL.
- Greeter-client registration, status-token rotation and credential
  enable/disable from the server's local administration mode commit their
  mutation with `client_registered`, `client_token_rotated`,
  `client_disabled` or `client_enabled`. A new one-time token is printed only
  after the database and audit transaction commits.
- Denial events remain denials when their audit write fails.

All success events currently emitted by the HTTP application are now durable
before success is returned, and state-changing events use transaction-owned
methods. The same policy now covers the separate `identity-admin` CLI and local
greeter-client administration. PostgreSQL HTTP contracts additionally prove
that audit rejection during first-user provisioning or first-subject assignment
exposes neither a redirect nor an authorization code, leaves no partial identity
state, and that competing token exchanges create exactly one success audit.

## Retention, export, rotation and monitoring

- The database audit table is the authoritative record. Identity performs no
  automatic audit-row deletion or truncation. This prevents silent loss before
  an archive policy is explicitly approved.
- A consistent SQLite online backup or PostgreSQL custom-format `pg_dump` is
  the supported lossless audit export. Keep exports root-readable, encrypted at
  rest when moved off-host, never commit them, and verify a restore before
  treating an export as recoverable.
- LOGIN01's daily maintenance keeps the existing rolling set of 50 consistent
  database backups for operational recovery. This rotates backup files, not
  audit rows. Removing old audit rows requires a separately reviewed archive,
  retention period and destructive maintenance command; none is authorized or
  implemented.
- Bounded operational messages with `component=audit` and an `event_type`
  identify audit-write failures without database errors or sensitive values.
  Monitor the service journal for these messages and alert on every occurrence;
  there is no acceptable steady-state failure rate for required success events.
- After restore or migration, validate aggregate audit counts and the newest
  event timestamp without printing event details. PostgreSQL reconciliation
  remains the field-complete database check.
- Human-readable ad-hoc exports are intentionally not provided yet. They would
  contain personal security history and require explicit access control,
  minimization and deletion rules before implementation.
