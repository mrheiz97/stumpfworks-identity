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
- Self-service lost-badge revocation and its success event are atomic on both
  backends; audit failure leaves the badge active.
- Denial events remain denials when their audit write fails.

Other successful mutations still use visible best-effort audit writes. They
must move to transaction-owned methods before PostgreSQL production cutover.
This is an explicit migration limitation, not permission to silently ignore an
audit failure.
