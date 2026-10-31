# Client device authentication

This document closes the design phase for stronger managed-client authentication.
It is a migration plan, not authorization to issue certificates or change a
production listener. The existing AD password fallback, Badge/PIN login, login
grant, PKINIT and Kerberos paths remain available throughout the migration.

## Implementation status

Identity v1.12.0 is published and runs in production on LOGIN01 with PostgreSQL.
SQLite and PostgreSQL share the same client mode, enrollment-token and public
credential records. Initial enrollment, renewal, revocation and mode changes
are transactional and audited; enrollment and renewal are replay-safe, and the
URI SAN must exactly equal the registered client identity. Import,
reconciliation and backup/restore allowlists include both new tables.

The production foundation remains deliberately dormant: every existing client
uses `token_only`, no device CA or certificate has been created, and no client
has been changed. The existing public listener on port 8080 is unchanged; the
separately opt-in mTLS status and enrollment listeners on ports 8444 and 8445
remain disabled. The listeners fail closed without distinct addresses, server
TLS files and the required device-CA material. Enrollment and renewal transport
are implemented:
bootstrap uses its own independently switchable HTTPS listener and a short-lived
single-use token; renewal requires the currently active mTLS credential. Both
accept only signed ECDSA P-256 CSRs and issue the canonical URI identity instead
of trusting CSR names. The managed-client installer, real PostgreSQL contracts,
Linux race tests and local interruption/rollback acceptance are complete. A
separately approved WYSE01 rollout with its own stopped rollback remains the
next gate.

The bootstrap listener must be enabled only for an intentional enrollment
window and disabled immediately afterwards. Operators issue a token with
`identity-admin client-enrollment issue --client-id <id> --minutes 10`. The
command prints the random token exactly once; only its SHA-256 hash is stored.
The device CA private key remains in a root-readable file and is never returned
by either endpoint.

On the managed client, `sw-badge-client-device enroll` generates the ECDSA P-256
private key locally, sends only the signed CSR and one-time token, validates the
returned certificate and writes a combined certificate/private-key bundle with
mode `0600`. The enrollment command refuses to overwrite an existing bundle.
`sw-badge-client-device renew` authenticates with the current bundle, generates
a new key and replaces the bundle only after the new response passes chain,
identity, EKU, expiry and public-key checks. Enrollment and renewal are first
staged for at most ten minutes. After atomic installation, the new certificate
must activate itself over mTLS; only that transaction makes it active and, for
renewal, supersedes the old credential. Failed activation restores the old local
bundle, while the server continues accepting the old credential. A fresh pending
credential blocks parallel issuance. `sw-badge-client-status` accepts the same
bundle through `SWBADGE_DEVICE_BUNDLE_FILE`; the bearer token is deliberately
retained during the migration window.
Renewal additionally pins the previously installed device CA; changing that CA
requires a separate, explicitly reviewed rotation procedure and cannot happen
silently through an ordinary renewal response.

Example commands (tokens and private material must never be pasted into shell
history):

```text
sw-badge-client-device enroll --server https://login01.example.test:8445 \
  --activation-server https://login01.example.test:8444 \
  --client-id wyse01-greeter --enrollment-token-file /run/credentials/enrollment

sw-badge-client-device renew --server https://login01.example.test:8444 \
  --client-id wyse01-greeter
```

## Current boundary

`POST /api/v1/client/status` currently authenticates a registered client with a
random bearer token. The client stores that token in a root-only file and
Identity stores only its SHA-256 hash. HTTPS validates LOGIN01 with the Homelab
CA. Token rotation and client disable/enable are transactionally audited.

Badge authorization accepts a bounded `client_id`; PKINIT then redeems a
30-second, single-use grant bound to the same ID. This prevents moving a grant
between client IDs, but neither request currently proves possession of a
device-specific credential. The status token must therefore not be treated as
a general badge- or PKINIT credential.

## Target architecture

Use mutual TLS for machine-to-machine client APIs, starting only with status
reports. Keep the existing HTTPS server certificate and create a separate
StumpfWorks device CA. The device CA must not reuse the server TLS CA or the
PKINIT CA.

- Generate each private key on its device. Store it root-only; prefer a TPM or
  another non-exportable key provider when a client supports one. LOGIN01 never
  receives or backs up a device private key.
- Issue a certificate with `clientAuth` EKU and one exact URI SAN containing
  the canonical client ID, for example
  `urn:stumpfworks:identity:client:wyse01-greeter`. Do not derive identity from
  the certificate common name.
- Verify the chain, validity interval, client EKU and exact SAN before looking
  up the enabled client. Also require an active database credential record
  whose certificate fingerprint and serial match. A TLS-valid certificate is
  not sufficient after administrative revocation.
- Store only the public certificate metadata and SHA-256 fingerprint. Never
  store private keys, bootstrap credentials or raw bearer tokens in the
  database, audit log or web interface.
- Use bounded certificate lifetimes. Renewal is authenticated by the current
  valid certificate and commits the new credential and audit event together.
  Initial enrollment uses a short-lived, single-use bootstrap token delivered
  outside the browser UI. Consuming it and recording the first credential must
  be transactional and replay-safe.

Do not require a client certificate on the existing public HTTPS listener.
Browser administration, OIDC, self-service and fallback login share that
listener. The preferred deployment is a dedicated client-API listener with
`RequireAndVerifyClientCert`. If a reverse proxy is used instead, it must pass
verified certificate identity through an authenticated local boundary and
strip all client-supplied identity headers. Application code still performs
the database status and SAN-to-client-ID checks.

## Compatibility and rollout

Each client has an explicit authentication mode:

1. `token_only` — current behaviour and the migration default.
2. `certificate_preferred` — a valid device certificate is used when present;
   the existing status token remains an emergency fallback and its use is
   visibly audited and monitored.
3. `certificate_required` — status reports require the active certificate;
   bearer authentication is rejected for that client.

The server is deployed before any client changes. WYSE01 is enrolled first,
then observed through at least one offline/reconnect window, one certificate
renewal and one updater rollback. Only after those checks may WYSE01 move to
`certificate_required`. MOBILE01 is outside this phase and remains
`token_only` until its separate future acceptance.

The bearer token is retained, not deleted, during the first required-mode
window. Rollback consists of changing only that client back to
`certificate_preferred` or `token_only`; it does not alter Badge/PIN, PKINIT,
LightDM, Winbind or PAM. Token deletion is a later, separately approved cleanup
after the certificate path and its recovery procedure are proven.

### WYSE01 rollout gates

Treat each numbered stage as a separate stop point. A later stage is not
implicitly authorized by completing an earlier one.

1. Read-only preflight: verify the registered client ID, current `token_only`
   mode, recent status, LightDM, status timer, AD join, disk space, clock,
   server TLS validation and an empty relevant warning journal.
2. Stopped rollback: preserve the installed client binaries, root-only
   configuration and credentials, systemd units/drop-ins and the complete
   device-bundle target directory. Record and verify SHA-256 hashes without
   printing credential contents.
3. Server preparation: create the dedicated device CA and listener credentials
   root-only, enable only the mTLS status listener, and verify that the public
   8080 listener and all browser routes are unchanged. Keep bootstrap 8445
   disabled outside the short enrollment window.
4. Enrollment: issue one ten-minute token to a protected transient file,
   briefly enable bootstrap, enroll WYSE01, activate the staged credential,
   remove the transient token file and disable bootstrap immediately.
5. Preferred observation: set only WYSE01 to `certificate_preferred`; retain
   its bearer token and verify certificate status plus the audited token
   fallback. Exercise one full offline/reconnect window.
6. Recovery proof: exercise one certificate renewal and one interrupted updater
   rollback. Confirm the previous credential and client bundle remain usable
   after every deliberately failed activation.
7. Required mode: only after a fresh explicit approval, set only WYSE01 to
   `certificate_required`, verify status reporting, then prove the per-client
   rollback to `certificate_preferred` or `token_only`.
8. Regression acceptance: verify normal AD password fallback, Badge/PIN,
   PKINIT, Kerberos, LightDM, browser administration, OIDC and server backup.
   Confirm that logs, diagnostics, Git and support artifacts contain no private
   key, certificate body, enrollment token or bearer token.

MOBILE01 remains excluded from all stages. Badge authorization and PKINIT are
not moved to certificate authentication as part of this rollout.

Badge authorization and PKINIT are a later phase. They may reuse the verified
device identity only after the status rollout is stable. At that point the
server must compare the certificate identity, request `client_id`, login-grant
binding and enabled client record. They must not be migrated implicitly with
the status endpoint.

## Data and audit contract

Add a separate device-credential table rather than overloading `clients` or
the status-token hash. Its SQLite and PostgreSQL forms must represent the same
fields:

- immutable credential ID and client foreign key;
- certificate SHA-256 fingerprint and serial in canonical form;
- URI SAN, public-key algorithm, issuer identifier, issue and expiry times;
- status (`pending`, `active`, `superseded`, `revoked`), optional superseded
  credential reference and optional revocation time;
- creation and update times.

Only one active credential is accepted unless an explicitly bounded renewal
overlap is in progress. Unique constraints prevent reusing a fingerprint or
serial. Enrollment, renewal, revocation and authentication-mode changes use
transactional, fail-closed audit events. Audit details contain only bounded
reason codes and public certificate identifiers; they contain no key material,
bootstrap token, bearer token, CSR body or certificate body.

The existing database import, reconciliation, backup/restore and known-table
allowlists must include the new table before a production migration. Client
disable remains authoritative and rejects both token and certificate status
authentication.

## Required acceptance tests

Implementation is not complete until these cases pass for SQLite and real
PostgreSQL, including race-enabled CI where applicable:

- valid certificate and exact SAN/client-ID binding;
- unknown CA, wrong issuer, wrong EKU, missing or duplicate identity SAN;
- expired and not-yet-valid certificate;
- fingerprint/serial mismatch, revoked credential and disabled client;
- bootstrap replay, renewal replay and concurrent renewal;
- audit failure rolls back enrollment, renewal, revocation and mode changes;
- a certificate cannot downgrade another client to bearer authentication;
- dedicated-listener TLS policy and rejection of forged proxy headers;
- backup, restore, migration and reconciliation preserve every public field;
- offline/reconnect, interrupted update and automatic rollback still work;
- browser admin, OIDC, local AD password fallback, Badge/PIN, PKINIT and
  Kerberos behave exactly as before.

Production acceptance additionally requires a current LOGIN01 backup, a
root-only rollback of binaries/configuration, certificate-expiry monitoring,
an exercised per-client mode rollback and confirmation that no private key or
credential appears in logs, diagnostics, backups intended for support, or Git.

## Framework boundary

The reusable certificate mechanics belong in StumpfWorks Framework after their
contract is proven here: strict URI-SAN extraction, chain/EKU/time validation,
canonical public metadata, constant-time fingerprint comparison, and safe TLS
client construction. A generic enrollment-token primitive may move there only
if another product needs the same replay and expiry contract.

Identity retains product policy: client records and modes, device-credential
schema, transactional audit event names, admin workflows, endpoint selection,
Badge/PIN and PKINIT binding, rollout order and rollback decisions. Framework
code must not learn Identity database tables or authorize a StumpfWorks client
by itself.
