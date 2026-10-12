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
  secrets are printed only after the transaction commits.
- Denial events remain denials when their audit write fails.

All success events currently emitted by the HTTP application are now durable
before success is returned, and state-changing events use transaction-owned
methods. The same policy now covers the separate `identity-admin` CLI. A real
PostgreSQL migration, backup/restore, cutover and reconciliation rehearsal is
still required before production cutover.
