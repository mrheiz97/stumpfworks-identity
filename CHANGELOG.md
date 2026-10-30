# Changelog

All notable changes to StumpfWorks Identity are documented here.

## [Unreleased]

### Added

- Added the backend-neutral database foundation for gradual managed-client
  certificate authentication: explicit per-client modes, single-use enrollment
  records and public device-certificate metadata on SQLite and PostgreSQL.
- Added transactional, audited enrollment, renewal, revocation and mode changes,
  including replay protection and exact URI-SAN binding to the registered client.
- Added a separately opt-in mTLS client-API listener restricted to status
  reports. Its dedicated device-CA trust, certificate identity extraction and
  database credential match do not affect the browser/OIDC listener.
- Added a separately switchable HTTPS bootstrap listener for one-time device
  enrollment and an mTLS-only renewal endpoint. `identity-admin` can issue a
  5–60 minute single-use enrollment secret whose hash alone is stored.
- Added `sw-badge-client-device` for local ECDSA P-256 key generation,
  enrollment and authenticated renewal. It verifies the returned chain,
  client identity, usage, expiry and public key before installing one root-only
  certificate/private-key bundle through an atomic file replacement.
- Added an explicit ten-minute activation stage. Enrollment and renewal remain
  pending until the newly installed certificate proves possession over mTLS;
  interrupted renewal leaves the previous active credential usable and restores
  the previous local bundle.

### Security

- Kept every existing client in `token_only` by default. No listener, productive
  client or existing Badge/PIN, PKINIT, Kerberos or fallback path is changed.
- Added rollback contracts proving that an audit failure cannot consume an
  enrollment token or partially replace a device credential.
- Certificate-preferred bearer fallback is explicitly audited in the same
  transaction as its status update. Invalid presented certificates cannot
  downgrade to bearer authentication, and certificate-required mode rejects it.
- Device CSRs must carry a valid ECDSA P-256 proof of possession. Identity
  ignores requested names and issues exactly one canonical client URI SAN;
  enrollment consumption and renewal replacement remain transactionally audited.
- Client status reporting can load the same device bundle for mTLS while the
  existing bearer-token file remains available for the controlled migration
  rollback.
- Renewal pins the already installed device CA and rejects an unexpected CA
  change; CA rotation remains a separate operational procedure.
- A fresh pending credential blocks parallel issuance and cannot supersede the
  active credential until its final activation and audit event commit together.

## [1.11.0] - 2026-10-29

### Changed

- Rebuilt the administration interface around the approved compact
  StumpfWorks operations design: denser navigation, ordered live store
  counters, a service overview, compact forms and tables, and responsive
  layouts without introducing a client-side framework.
- Unified OIDC clients, OIDC sessions, system status and PIN management with
  the same server-rendered sidebar and active navigation as the core Identity
  pages. Login and Self-Service use a quieter variant of the same design.

### Security

- Preserved server-side role filtering, CSRF fields, CSP, secret-free browser
  state and every existing mutation endpoint. Shared navigation is generated
  from the current request permissions and does not expose unauthorized
  sections.
- Added rendering contracts for the compact stylesheet, live database counts,
  shared standalone-page shell and the unprotected local preview boundary.

## [1.10.0] - 2026-10-29

### Added

- Added transactional central OIDC revocation for every active session owned
  by one user, issued to one client, or present globally during an incident.
- Added protected controls to the existing OIDC sessions page with CSRF,
  bounded validation and explicit `revoke-all` confirmation.

### Security

- Bulk revocation and its aggregate, data-minimal audit event commit together
  on SQLite and PostgreSQL. Audit failure rolls back every affected session;
  concurrent or repeated requests cannot create a second successful mutation.

## [1.9.0] - 2026-10-29

### Added

- Added a root-only PostgreSQL custom-format backup helper and an explicit
  post-cutover systemd drop-in. Credentials remain in a libpq service file,
  every dump is validated with `pg_restore --list`, and the success marker is
  advanced only after certificate and backup checks pass.

### Operations

- Documented the completed LOGIN01 PostgreSQL 17 production migration,
  least-privilege role split, stopped SQLite reconciliation, and successful
  restore rehearsals.

### Security

- Made current self-service logout and redeemable OIDC-code denial atomic with
  their audit records on SQLite and PostgreSQL. Audit rejection now preserves
  the session or code and exposes no false success.
- Added data-minimal audit coverage for rejected administrator authentication
  and stopped HTML administration routes from hiding transactional audit
  failures behind normal redirects.

## [1.8.0] - 2026-10-26

### Added

- Added opt-in, privacy-bounded Identity metrics for build/start state,
  modules, component outcomes and latency, audit write failures, aggregate
  objects, client freshness/health, TLS expiry, backup age and maintenance.
- Reused Framework v1.0.0 HTTP, LDAP and PostgreSQL pool instrumentation and
  connected the existing runtime PostgreSQL pool without a duplicate metrics
  implementation.
- Added per-source throttling for failed metrics bearer authentication,
  scrape-time collector deadlines, fixed label vocabularies, privacy and
  cardinality tests, Prometheus scrape/rule examples and a Grafana dashboard.

### Security

- Metrics never label or expose usernames, badge or OIDC identifiers, client
  IDs, IP addresses, DNs, file paths, tokens, free-form audit details or raw
  errors. Unknown routes and results collapse to bounded categories.

## [1.7.1] - 2026-10-26

### Fixed

- Fixed the deliberately small YAML reader treating an indented empty value
  such as `cert_sha256:` as a new top-level section. Keys following such a
  value now remain in their actual section, preventing optional administrative
  role mappings from being silently skipped.
- Added regression coverage for empty values in the directory and OIDC
  sections. Existing quoted empty values and non-empty configuration remain
  compatible.

## [1.7.0] - 2026-10-26

### Added

- Added disabled-by-default, time-limited emergency administration for a
  directory outage. Root-only local commands issue, list and revoke 5–60 minute
  grants; the clear token is shown once and only its SHA-256 hash is persisted.
- Added a separate `emergency-admin` browser audience backed by a random hashed
  server-side session. Every request checks expiry and revocation without LDAP,
  while normal AD administration remains unchanged.
- Added SQLite and PostgreSQL schema, import, reconciliation and concurrency
  contracts for exactly-once exchange and immediate revocation.
- Added a guarded rollout, acceptance and rollback runbook that preserves AD
  password fallback, Badge/PIN, Greeter, Passkeys, OIDC, PKINIT and Kerberos.

### Security

- Grant issuance, successful exchange, explicit revocation and logout
  revocation commit atomically with data-minimal audit events. Audit failure
  rolls back the corresponding state transition.
- Emergency tokens, token hashes and session hashes are excluded from browser
  listings and audit details. Login failures remain generic and rate-limited.

## [1.6.0] - 2026-10-26

### Added

- Added optional recursive AD group mappings for Identity, OIDC and client
  operators plus a read-only auditor. The existing administrator group remains
  the unrestricted recovery role, and installations without optional mappings
  retain their previous behavior.
- Added a server-side permission matrix shared by HTML and JSON administration
  routes. Current group membership is resolved for every privileged request;
  membership removal and directory failures therefore fail closed without
  waiting for the signed cookie to expire.
- Added permission-aware navigation, mutation controls and a dedicated
  read-only OIDC operations view. UI visibility remains a usability feature;
  direct requests are independently authorized by the server.
- Added SQLite and PostgreSQL authorization contracts covering bounded roles,
  direct denied writes, transactional operator changes and audit, role unions,
  unknown roles, role removal, LDAP failure and legacy administrator
  compatibility.
- Added production rollout and rollback guidance with empty-group compatibility,
  one-role-at-a-time activation and preserved OIDC, AD-password, Passkey,
  Badge/PIN, Greeter, PKINIT and Kerberos acceptance checks.

### Security

- Administrative cookies continue to contain only their audience, username
  and expiry. Role names and AD group DNs are neither stored in the browser nor
  emitted as OIDC claims.
- Logout remains available with a valid session-bound CSRF proof after role
  removal or during a directory outage; other privileged requests fail closed.
- Duplicate configured role group DNs are rejected at startup, including
  case-only duplicates, to prevent ambiguous policy assignments.

## [1.5.0] - 2026-10-25

### Added

- Added a disabled-by-default WebAuthn foundation with strict RP/origin policy,
  discoverable-login options requiring user verification, stable opaque user
  handles, and short-lived single-use ceremony storage on SQLite and
  PostgreSQL. Credential registration now commits public credential data,
  ceremony consumption and a data-minimal audit event atomically on both
  backends. Successful authentication can atomically update credential state,
  create an existing revocable 15-minute self-service session, consume the
  ceremony and write its data-minimal audit event, including fail-closed audit,
  counter-regression and concurrent-replay contracts.
- Added bounded discoverable-assertion verification to the pinned WebAuthn
  adapter with exact saved RP/origin binding, opaque user-handle lookup,
  required user verification, signature validation and fail-closed clone
  warning handling.
- Added bounded Passkey registration verification with exact RP/origin/user
  binding, discoverable credentials, required user verification, existing
  credential exclusion and forged-attestation rejection.
- Added explicitly opt-in Self-Service JSON endpoints for registration and
  discoverable login. They are absent by default; registration requires the
  current revocable session, CSRF and fresh AD-password confirmation, while
  login uses rate limits, generic failures and the existing 15-minute session.
  No browser controls or production configuration are enabled.
- Added a full local HTTP integration test covering fresh AD-password and CSRF
  registration, a real signed P-256 WebAuthn credential, persisted credential
  and audit state, discoverable login, Self-Service cookie issuance and replay
  rejection.
- Added opt-in Self-Service browser controls for Passkey registration and
  discoverable login. The external CSP-compatible script performs only the
  WebAuthn binary conversions, keeps AD-password login available, reports
  cancellation without account disclosure and is not served while Passkeys
  are disabled.
- Added an opt-in metadata-only view of the current user's active Passkeys.
  It shows only the bounded name, creation/last-use time and whether the
  authenticator is device-bound or sync-capable; credential IDs, public keys,
  user handles and counters never reach the template.
- Added random Passkey management identifiers and transactional Self-Service
  revocation on SQLite and PostgreSQL. Revocation requires the active session,
  CSRF and a fresh AD-password check; credential state and the data-minimal
  `passkey_revoked` audit event commit together or both roll back.
- Added the guarded LOGIN01 rollout and rollback procedure plus the real
  Chromium, platform-authenticator, optional security-key and fallback
  acceptance checklist. The procedure does not enable the feature.

### Operations

- Completed a guarded LOGIN01 Self-Service pilot with Chrome and Windows Hello.
  Registration, discoverable login, cancellation, wrong-password rejection,
  transactional revocation, revoked-credential rejection and AD-password
  recovery passed with matching data-minimal audit events. The pilot retained
  a verified root-only rollback and ended with no active test Passkey.

## [1.4.1] - 2026-10-21

### Added

- Added a self-restoring offline-test helper that schedules and verifies its
  reconnect before disconnecting a managed NetworkManager interface.
- Added a read-only client release acceptance mode that verifies the signed
  package, exact installed components, matching rollback and service health as
  one operation.
- Documented a staged device-certificate architecture with a dedicated client
  API listener, per-client compatibility modes and explicit SQLite,
  PostgreSQL, audit and rollback requirements.

### Security

- Client release acceptance is now a single fail-closed updater mode covering
  the signed package, exact installed component hashes and modes, the matching
  complete rollback, and non-disruptive service health checks. It cannot
  install or restore files and does not restart LightDM or VNC.
- Client updates now persist a root-only transaction marker before the first
  file replacement. The periodic status service recovers an interrupted
  installation from its fully validated, fixed-target rollback before sending
  another report, records the recovered failure and retains the marker when
  recovery itself cannot be completed safely.
- The signed update allowlist now includes the updater binary so deployed
  clients can receive the crash-recovery implementation through the same
  verified package format.

## [1.4.0] - 2026-10-20

### Added

- Added a production-tested OpenID Connect provider with Authorization Code
  Flow, PKCE S256, exact redirect allowlists, stable opaque subjects, Discovery,
  JWKS and controlled signing-key rotation.
- Added protected OIDC client administration for registration, activation,
  deactivation, secret rotation, exact multi-redirect configuration and
  per-client scopes.
- Added server-side OIDC sessions with opaque access tokens, authenticated
  introspection, revocation and immediate logout in StumpfWorks Access.
- Added a protected OIDC operations view for public signing-key metadata,
  client state, redirect counts and linked/unlinked identity status without
  exposing subjects, secrets, hashes or private key paths.
- Added a shared SQLite/PostgreSQL application-store contract, explicit
  PostgreSQL schema migrations and guarded import/reconciliation tooling.

### Changed

- Identity now uses StumpfWorks Framework v1.0.0 for the shared integration
  contracts while preserving existing Badge/PIN, PKINIT, Kerberos and AD
  password fallback paths.
- Successful authentication, credential issuance and administrative mutations
  now use transactional, fail-closed audit boundaries on SQLite and PostgreSQL.
- `identity-admin` now uses the same configured runtime store as the server.

### Security

- Badge authentication now commits its last-use marker and success audit
  atomically before retaining or returning a login grant on both SQLite and
  PostgreSQL.
- PKINIT certificate responses now fail closed when their success audit cannot
  be persisted; the consumed one-time grant remains non-reusable.
- OIDC authorization codes are created atomically with login, consent and
  issuance audit events. Token exchange commits code consumption together with
  its success audit before returning any token material. First-login user and
  stable-subject creation are transactionally audited as well.
- Administrator and self-service login, PIN changes, user provisioning and
  administrative badge lifecycle operations now fail closed or roll back when
  their required success audit cannot be persisted.
- `identity-admin` now uses the configured SQLite/PostgreSQL runtime store and
  atomically audits OIDC client creation, secret rotation, enable/disable and
  initial subject assignment before reporting success or revealing a new
  one-time secret.
- Added a guarded SQLite-to-PostgreSQL migration utility with read-only source
  handling, explicit mutation confirmations, bounded import and exact
  aggregate-only reconciliation, plus a stop-the-world cutover and rollback
  runbook.
- Added SQLite and PostgreSQL protocol coverage for OIDC client-secret
  rotation: the old secret is rejected immediately, the replacement succeeds,
  failed old-secret authentication does not consume the authorization code and
  audit records contain no secret material.
- Added end-to-end `identity-admin` command coverage on SQLite and PostgreSQL
  for client creation, one-time secret output, secret rotation, disable/enable,
  stable subject creation and the corresponding audit records.
- Greeter-client registration, status-token rotation and credential state
  changes now commit with their success audit on SQLite and PostgreSQL before a
  one-time token or success result is returned.
- PostgreSQL OIDC protocol tests now fail first-login user and subject creation
  closed on audit rejection and require exactly one success audit across
  competing token exchanges.
- The protected administration interface can now list, register, rotate,
  disable and enable OIDC clients. Mutations require CSRF validation, use the
  existing transactional audit boundary and reveal a new secret only in the
  immediate successful response; listings never expose secret hashes.
- OIDC access tokens are now opaque, stored only as SHA-256 hashes and tied to
  server-side sessions. Authenticated RFC 7662 introspection, RFC 7009
  revocation and a protected administrative session view make active grants
  centrally revocable on SQLite and PostgreSQL.
- Token issuance now commits authorization-code consumption, the revocable
  session and its audit event together. Revocation also fails closed with its
  audit, and disabling a client permanently revokes all of its active sessions.

## [1.3.0] - 2026-08-29

### Added

- Self-service users can view only their own active badges with bounded issue and last-use metadata; badge tokens and other users' badges remain inaccessible.
- Self-service users can report one of their own active badges as lost, immediately disabling it with ownership enforcement, CSRF protection and an audit event.
- Self-service users can review their latest 20 badge sign-ins with only timestamp, badge code, client ID and result; IP addresses, audit details and other users' events remain hidden.
- Administrator-issued replacement badges remain disabled until their assigned owner activates the one-time payload in self-service.
- Self-service sessions are tracked server-side so users can view active sessions and revoke every other session without ending the current browser session.
- The badge administration page can issue a pending replacement and display its one-time activation payload without requiring direct API use.

## [1.2.1] - 2026-08-28

### Added

- Server-side client registration with one-time random credentials stored only as hashes.
- Authenticated, data-minimized client health reporting and a protected client-list API.
- A hardened one-shot Linux status collector with a periodic systemd timer.
- A protected administrative client-health overview with explicit stale-report detection.
- Local client-token rotation and reversible status-credential disabling without exposing secrets to the web interface.
- Client/server semantic-version comparison with an update-availability indicator in the protected status page.
- Root-only, privacy-limited client diagnostic archives and an automatic post-installation system check.
- Verification-only client updater with signed manifests, fixed components, architecture checks and package-integrity limits.
- Isolated atomic staging with fixed installation targets, a machine-readable plan and a second payload-integrity check.
- Atomic rollback snapshot preparation with source hashes, missing-file records and symlink rejection.
- Prevalidated, resumable rollback restoration with atomic file replacement and failure-injection tests.
- Atomic installation transaction with automatic rollback and tampered-stage rejection.
- Mandatory post-install health gate with automatic restoration after an injected unhealthy result.
- Component-aware systemd health orchestration and an explicit maintenance-window requirement for greeter updates.
- Guarded client-updater installation mode with mandatory fresh staging and rollback paths.
- Post-rollback systemd recovery checks and explicit LightDM restart handling for approved greeter maintenance.
- Create-only Ed25519 development key generation and signed update packaging with fixed component validation.
- Privacy-bounded client update outcome reporting with target version, timestamp and rollback availability.
- Admin system-status history for the last reported client update, including success or failure.
- Greeter maintenance now rebinds the current persistent `swbadge-vnc.service` instead of the retired transient unit.
- Separate configurable managed-client target version from the running LOGIN01 build version.

## [1.1.0] - 2026-08-26

### Added

- Pre-login LAN/WLAN state and a NetworkManager-backed Wi-Fi chooser.
- Generic guided Linux-client installation with role-specific validation and rollback files.
- Root-controlled shared client configuration for the greeter and PAM helper.
- Persistent, password-protected VNC service template with a safe loopback default.
- Polkit policy restricted to the dedicated LightDM greeter account.
- Public repository hygiene, CI, contribution guidance and security reporting policy.
- An anonymized native-greeter screenshot and expanded project documentation.

### Changed

- Renamed the project from StumpfWorks Badge Login to StumpfWorks Identity.
- Improved native-greeter buttons, pointer visibility and device-name handling.
- Replaced deployment-specific examples with reserved `example.test` values.
- Moved development to a dedicated `development` branch while keeping `main` release-only.
- Updated the Go module path for the new repository.

### Fixed

- Ensured the greeter and PAM helper use one TLS-verified hostname and CA configuration.
- Ensured LightDM can read the trusted CA without exposing root-only client files.
- Preserved Kerberos-backed FILE01 mounts after badge authentication.
- Normalized Windows line endings during guided Linux-client installation.

### Compatibility

Existing `SWBADGE_*` environment variables, API paths, badge payloads and installed file names remain supported. No badge reissue or database migration is required.

## [1.0.0] - 2026-08-23

- Initial stable release with native LightDM badge/PIN login, AD password fallback, one-time grants, PKINIT, Kerberos TGT creation, CIFS mounts, administration, PIN self-service, auditing, backups and certificate monitoring.
