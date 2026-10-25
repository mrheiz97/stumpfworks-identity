# Passkey Self-Service rollout and rollback

This runbook covers the first controlled activation of the opt-in Passkey
Self-Service on LOGIN01. It does not enable Passkeys by itself. Badge/PIN,
AD-password Self-Service, the Access OIDC login, PKINIT, Kerberos and the
Greeter must remain available throughout the maintenance window.

## Change boundary

- Change only LOGIN01's Identity binary, SQLite schema and the three
  `passkeys` configuration values.
- Keep `database.backend: sqlite`; this is not the PostgreSQL cutover.
- Do not change LDAP, OIDC, PKINIT, TLS, client or Greeter configuration.
- Use the externally visible values exactly:
  `rp_id: login01.ad.stumpfworks.de` and
  `origin: https://login01.ad.stumpfworks.de:8080`.
- Never print or copy the session secret, LDAP bind password, OIDC material,
  private TLS key, credential IDs, public keys or WebAuthn ceremony bodies.

## Read-only gate

Before creating a rollback or stopping the service, record only bounded
results:

1. `development` CI for the exact build commit is successful, including the
   real PostgreSQL contract and race detector.
2. The installed service is active and its journal has no current warning or
   error burst.
3. The installed binary hash and version are recorded without reading secret
   files.
4. The root-owned configuration and secret-file modes are unchanged.
5. The configured TLS certificate is valid for
   `login01.ad.stumpfworks.de`, matches its key and is not near expiry.
6. `/api/v1/health`, `/self-service`, OIDC discovery and JWKS succeed with
   full CA and hostname verification.
7. A read-only SQLite `integrity_check` returns exactly `ok`; the most recent
   scheduled backup exists and is root-only.
8. `passkeys.enabled` is still false before the maintenance window.

Stop if any item differs from the known healthy state.

## Rollback creation

Create one timestamped root-only directory before installation. It must contain
the previous server binary, its SHA-256 digest, the systemd unit and drop-ins,
the root-owned configuration and a consistent stopped-service SQLite copy.
Record file ownership and modes. Do not copy unrelated secrets into transport
or user-readable locations.

The database copy is taken only while Identity is stopped. Verify the copy with
`integrity_check` before proceeding. Start the old service again if the
maintenance window cannot continue immediately.

The first start of the new binary adds and backfills the random
`management_id` column for existing WebAuthn credentials. The released v1.4.1
binary tolerates the additional table/column because it has no Passkey routes,
but rollback must restore both the previous binary and configuration with
Passkeys disabled. Restore the SQLite copy as well if the new build has accepted
any Passkey registration, authentication or revocation write.

## Controlled activation

1. Stop Identity and confirm the process is gone.
2. Create and verify the rollback described above.
3. Install the CI-tested binary atomically with the existing owner and mode.
4. Add only the exact `passkeys` block and keep it disabled for the first
   start.
5. Start Identity. Confirm schema migration, SQLite integrity, service health,
   journal, AD-password Self-Service, OIDC discovery/JWKS and Access readiness.
6. Stop Identity, change only `passkeys.enabled` to true, start it and repeat
   health, journal and TLS checks.
7. Confirm that the unauthenticated Self-Service still shows the unchanged AD
   password form and additionally the Passkey choice. No Passkey control may
   appear on the administrator login page.

Do not combine this window with PostgreSQL, key rotation, OIDC client changes,
client updates or Greeter work.

## Chromium and authenticator acceptance

Use current Chrome or Edge against the real verified HTTPS hostname. Do not
bypass certificate warnings and do not capture Windows Hello, biometric or
security-key prompts in screenshots.

1. AD-password sign in to Self-Service still succeeds.
2. Registration rejects a wrong current AD password and leaves no credential
   or success audit.
3. Register one platform Passkey with a non-identifying label. Confirm exactly
   one `passkey_registered` event and the bounded metadata row.
4. Sign out and use discoverable Passkey login. Confirm the normal 15-minute
   Self-Service session, exactly one `passkey_login` event and no administrator
   session.
5. Cancel a second registration and a login prompt. Both remain generic and
   create no success state.
6. Replay the completed browser request only through the existing automated
   test; do not extract a production assertion from browser tooling.
7. If an external FIDO2 security key is available, repeat registration and
   login with that key. If none is available, record the hardware-key test as
   pending rather than weakening the gate.
8. Remove the test Passkey using the current AD password. Confirm it disappears,
   cannot authenticate and produces exactly one data-minimal
   `passkey_revoked` event.
9. Repeat AD-password Self-Service login after removal to prove recovery.
10. Confirm Access OIDC login, Badge/PIN, normal AD-password fallback, PKINIT
    and Kerberos remain unchanged using their established smoke tests.

The browser operator performs Windows Hello or security-key confirmation
personally. No automation enters passwords or approves an authenticator prompt.

## Immediate rollback

Rollback immediately on schema error, repeated service warning, TLS/CSP error,
failed AD fallback, account-disclosing response, missing audit, or any effect on
OIDC, Badge/PIN, PKINIT or Kerberos.

1. Stop Identity.
2. Restore the previous binary and configuration with Passkeys disabled.
3. If any Passkey write occurred, restore the stopped-service SQLite copy. If
   no write occurred, retaining the additive management-ID migration is safe,
   but restoring the complete copy is the simpler verified boundary.
4. Restore original ownership and modes, reload systemd only if its files were
   changed, and start Identity.
5. Verify SQLite integrity, health, journal, AD-password Self-Service, OIDC
   discovery/JWKS, Access login and the established Badge/PKINIT checks.

Keep the rollback until the browser, audit and fallback acceptance has been
reviewed and a later release decision is made.

## Production pilot on 25 October 2026

The controlled Self-Service pilot completed on LOGIN01 using the unchanged
`development` commit `b903e00` (`1.5.0-dev`). The transferred binary hash was
verified before installation and after the final start. A stopped-service,
root-only rollback containing the previous binary, configuration, systemd
files and an integrity-checked SQLite copy is retained at
`/root/identity-passkey-rollback-20261025T094454Z`.

The first start kept Passkeys disabled. Schema, SQLite integrity, TLS,
Identity health, Self-Service, OIDC Discovery/JWKS and Access readiness passed
before the separate activation. Chrome with Windows Hello then confirmed one
platform-Passkey registration, discoverable login, the revocable 15-minute
session, generic cancellation responses, wrong-AD-password rejection,
transactional revocation, rejection of the locally retained revoked credential
and successful AD-password recovery. Audit counts matched each successful
registration, login and revocation. No credential identifier, public key, user
handle, ceremony body or secret was printed during acceptance.

The test ended with zero active Passkeys, an integral SQLite database, an
active service and no warning-level journal entries during the window. An
external FIDO2 security key was not available and remains an optional separate
hardware acceptance. Badge/PIN, Greeter, PKINIT and Kerberos configuration was
not changed during this window.
