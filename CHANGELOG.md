# Changelog

All notable changes to StumpfWorks Identity are documented here.

## [Unreleased]

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
