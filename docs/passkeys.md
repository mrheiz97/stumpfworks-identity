# Passkeys and WebAuthn

This document defines the staged Passkey/WebAuthn rollout for StumpfWorks
Identity. It is an implementation and acceptance contract, not authorization
to enable Passkeys on LOGIN01. Existing AD password authentication remains an
available recovery path throughout the rollout.

## Implementation status

`development` contains the first disabled backend increment. It adds identical
SQLite/PostgreSQL tables for opaque WebAuthn user handles, public credential
records and bounded one-time ceremonies. Import, reconciliation and
backup/restore treat those tables as part of the complete Identity dataset.

The pinned `go-webauthn` adapter accepts one exact HTTPS origin and matching RP
ID, rejects cross-origin operation, requires discoverable credentials and user
verification, and serializes the library session atomically for server-side
storage. Store contract tests require a stable random 32-byte user handle,
audience/type/expiry binding and exactly one successful consumer under
concurrency. No routes, browser JavaScript, configuration switch or production
migration are present, so this foundation cannot alter a login yet.

The design follows the W3C WebAuthn Level 3 recommendation and uses a pinned,
reviewed version of `github.com/go-webauthn/webauthn` behind an
Identity-owned adapter. The dependency remains pre-v1 and its credential and
origin-verification changes must be reviewed before every upgrade.

## Scope and order

Passkeys are introduced in three separately reversible increments:

1. Add backend storage, ceremony handling and tests while all routes remain
   disabled by configuration.
2. Enable registration and passwordless login only for normal self-service
   users. Registration requires a fresh successful AD-password verification;
   possessing an existing self-service cookie alone is insufficient.
3. Add administrator Passkey login separately. Every administrator assertion
   must be followed by a fresh directory lookup and current recursive
   administrator-group check before an admin session is issued.

OIDC authorization may reuse the resulting authenticated browser session only
after its audience and assurance are explicit. Badge/PIN, native Greeter,
PKINIT, Kerberos and managed-client authentication are outside this change.

## Relying-party boundary

- Production RP ID is exactly `login01.ad.stumpfworks.de` and contains no
  scheme or port.
- The allowed production origin is exactly
  `https://login01.ad.stumpfworks.de:8080`. Development and test origins are
  explicit configuration entries and never inferred from `Host` or forwarded
  headers.
- Cross-origin and iframe ceremonies are rejected. The current
  `frame-ancestors 'none'` policy remains in place.
- Registration and authentication require user verification, not only user
  presence. Discoverable credentials are required for passwordless login.
- Attestation defaults to `none`. This authenticates possession of the
  registered key but makes no hardware provenance claim. Enterprise
  attestation is a separate future policy decision.
- Each user receives a random, stable, non-identifying WebAuthn user handle of
  at least 32 bytes. Usernames, DNs, email addresses and OIDC subjects are not
  used as user handles.

## Ceremony lifecycle

Registration begins only after fresh AD authentication and creates a bounded,
server-side ceremony record. Authentication begins without revealing whether
a submitted username exists; the preferred passwordless flow uses a
discoverable credential and resolves the opaque user handle only after a valid
assertion.

Every ceremony has a cryptographically random identifier and challenge, an
exact type (`registration` or `authentication`), intended audience, optional
local user ID, creation/expiry timestamps and a single consumed timestamp.
Lifetime is at most five minutes. Completion locks and consumes the ceremony
before returning a session. Challenge, client data and responses are size
bounded and are never written to audit details or ordinary logs.

Registration commits the credential and `passkey_registered` audit event in
one transaction. Authentication commits ceremony consumption, signature
counter/backup-state changes, the new self-service session and
`passkey_login` audit event together. Any validation, storage or audit failure
returns no authenticated cookie and leaves no partially usable credential or
session. Replaying a successful response always fails.

The disabled backend foundation now implements that registration transaction
on SQLite and PostgreSQL. It validates bounded credential fields and the exact
RP ID, locks the intended registration ceremony, preserves the user binding,
stores only public credential material, writes a data-minimal audit event and
consumes the ceremony in one commit. Audit failure rolls the credential and
ceremony consumption back together. These store operations are not reachable
through HTTP and do not enable Passkeys.

The same inactive store boundary now completes successful discoverable
self-service authentication atomically. It locks the one-time ceremony and
active credential, enforces the resolved user binding and non-regressing
signature counter, updates the counter, backup state and last-use timestamp,
creates the existing maximum-15-minute revocable self-service session, writes
the data-minimal `passkey_login` audit event and consumes the ceremony in one
commit. Parallel replay has one winner. Session, credential state and ceremony
all remain unchanged when audit or persistence fails. Assertion parsing and
cryptographic verification remain inside the pinned adapter. The adapter now
performs bounded parsing, exact saved RP-ID/origin/session validation,
discoverable user-handle and credential resolution, public-key signature and
user-verification checks, backup-state handling and fail-closed clone/counter
warning rejection. It returns only the minimal verified state needed by the
transaction boundary.

Registration is now covered by the same pinned adapter boundary. It creates a
five-minute ceremony bound to the exact RP ID, HTTPS origin and opaque user
handle, requires discoverable credentials and user verification, excludes
already registered credentials and requests no attestation conveyance. The
bounded completion verifies client data, authenticator data, public-key
attestation and the user/session binding before returning only the durable
public credential projection used by the transactional store. Forged
attestation and cross-user completion tests fail closed. Fresh AD-password
confirmation and the HTTP feature switch remain deliberately outside this
adapter.

The JSON Self-Service integration now exists behind the explicit
`passkeys.enabled: true` switch, which defaults to false and therefore leaves
all four endpoints unregistered. Enabling also requires protected directory
mode plus an exact RP ID and HTTPS origin. Registration begin requires an
active revocable Self-Service session, its CSRF token and a fresh successful
AD-password check before the five-minute ceremony is stored. Discoverable
login is rate limited, returns generic failures and creates the existing
15-minute session only through the atomic store boundary. No browser
JavaScript or controls are shipped yet, so the feature remains inactive even
on an unchanged production configuration.

The server integration test exercises that complete boundary with a real
P-256 key pair and signed WebAuthn messages: password-confirmed and
CSRF-protected registration, transactional credential/audit persistence,
discoverable authentication, issuance of the existing revocable Self-Service
cookie session, and rejection of the identical replay. It does not contact or
modify LDAP, browsers, authenticators or production systems; the directory is
a deterministic local test double.

## Credential storage and lifecycle

SQLite and PostgreSQL use the same logical records:

- a stable random WebAuthn user handle linked to the local user;
- credential ID and public key bytes;
- RP ID and bounded user-visible credential name;
- public authenticator metadata required by the verifier, including transports,
  attestation format/type, flags, signature counter and backup eligibility/state;
- creation, last-use and optional revocation timestamps.

Credential IDs are unique. Raw private keys, biometric data, PINs, AD
passwords and authenticator secrets are never available to Identity. Audit and
administrative pages may show only the credential name, bounded public device
metadata, creation/last-use time and active/revoked status.

Users may register multiple Passkeys. Self-service removal requires an active
session, CSRF protection and fresh AD-password confirmation until at least one
independent recovery method has been explicitly accepted. Revocation commits
with `passkey_revoked` audit. A credential can never be re-enabled; registering
it again creates a new record.

Signature counters are evaluated according to the selected library's policy
and authenticator backup flags. A suspicious counter transition is denied and
audited with a bounded reason code, but counter value, credential ID and public
key are not placed in the general audit details.

## Sessions, fallback and privacy

Passkey self-service login creates the same 15-minute server-tracked
self-service session and signed `self-service` audience cookie as successful AD
password login. It does not mint an administrator cookie. Logout and “logout
other sessions” therefore work identically for both methods.

The AD-password form stays available and unchanged. Disabling Passkeys in
configuration removes the registration/login controls and rejects ceremony
routes without deleting credentials. Rollback requires only the previous
binary/configuration and does not alter directory, Badge/PIN, PKINIT, PAM,
LightDM, Kerberos or OIDC data.

Responses do not disclose whether a username, user handle or credential is
registered. Rate limits apply to ceremony creation and completion in addition
to existing login limits. Logs contain outcome, audience and bounded reason
only; credential IDs, challenges, user handles, public keys and assertion
bodies are excluded.

## Database and migration contract

The PostgreSQL migration must add WebAuthn users, credentials and ceremonies
without changing existing tables destructively. SQLite startup migration,
PostgreSQL import, reconciliation, backup/restore fixtures, restricted runtime
role and known-table allowlists must all cover the new records before the
feature can be enabled.

Persist a stable application-owned representation rather than an opaque Go
serialization. The adapter converts that representation to and from the pinned
library types. A library update that changes credential semantics requires an
explicit data-compatibility test and migration decision.

## Required tests

Both SQLite and real PostgreSQL must cover:

- successful registration and discoverable authentication with required user
  verification;
- exact RP ID and origin, with HTTP, alternate port, alternate hostname,
  cross-origin and forged forwarded-origin rejection;
- random opaque user handles that contain no account identifier;
- expired, wrong-type, already-consumed and concurrently completed ceremonies;
- challenge, credential ID, user handle, signature and UV/UP validation;
- duplicate credential, revoked credential and unknown credential behaviour;
- signature-counter and backup-state transitions;
- transaction rollback when credential, session or audit persistence fails;
- rate limits, request-size limits and generic account-enumeration-safe errors;
- session audience isolation, CSRF, logout and other-session revocation;
- disabled-feature behaviour and rollback to AD-password-only login;
- import, reconciliation, backup/restore and restricted PostgreSQL runtime;
- unchanged admin password, OIDC, Badge/PIN, PKINIT and Kerberos tests.

Browser acceptance must include current Chromium on the real HTTPS hostname,
one platform Passkey and one external security key if available. Registration,
login, cancellation, device loss, credential revocation and AD-password
recovery are exercised before production enablement. Private or biometric
authenticator material must never appear in screenshots, logs or test fixtures.

## Framework boundary

Identity initially owns the adapter and policy while the contract is proven.
Reusable RP/origin validation, bounded one-time ceremony storage interfaces and
safe conversion of public credential metadata are candidates for StumpfWorks
Framework. Identity retains user mapping, directory revalidation, session
audiences, database schema, audit event policy, route/UI behaviour and rollout
decisions. The Framework must not decide who is an Identity administrator or
silently change fallback policy.

## References

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [go-webauthn project](https://github.com/go-webauthn/webauthn)
- [go-webauthn release notes](https://github.com/go-webauthn/webauthn/releases)
