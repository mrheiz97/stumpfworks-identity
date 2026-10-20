# Security Policy and Model

SWBA combines a physical badge with a personal PIN and converts successful verification into short-lived credentials. It never stores or reconstructs the user's AD password.

## Credential handling

- Badge tokens contain 256 random bits; SQLite stores SHA-256 hashes only.
- PINs use Argon2id with random salts.
- Cleartext badge secrets appear only during issue or replacement.
- Grants last 30 seconds and are single-use and client-bound.
- Issued user certificates last ten minutes.
- Kerberos caches belong to the mapped user and use mode `0600`.
- AD passwords are verified over LDAPS and never stored or logged.

## Web controls

- Verified TLS is mandatory.
- Admin and self-service sessions have distinct signed audiences.
- Cookies are `Secure`, `HttpOnly` and `SameSite=Strict`.
- Browser writes require a session-bound CSRF token.
- Login and PIN attempts are rate-limited.
- CSP, HSTS, frame denial and restrictive permissions headers are enabled.
- Audit records exclude passwords, PINs, tokens, grants and private keys.
- OIDC access tokens are opaque and persisted only as SHA-256 hashes in
  short-lived server-side sessions. Introspection and revocation require the
  owning confidential client's credentials; administrative revocation requires
  an authenticated session and CSRF token. ID tokens remain valid until their
  five-minute expiry unless the relying application also enforces session
  introspection or back-channel logout.

## Operations

- Preserve the normal AD password fallback.
- Back up DC01 and LOGIN01 through Proxmox; snapshots are not backups.
- LOGIN01 creates daily consistent backups under `/var/backups/stumpfworks-badge` with mode `0600`.
- Daily checks fail 30 days before relevant certificates expire.
- Review `systemctl --failed` and timer results after upgrades and monthly.
- Revoke lost badges and rotate suspected secrets immediately.

Future AD writes must use a dedicated least-privilege account, protect privileged groups, require explicit confirmation for destructive actions and audit before and after state.

Never include real credentials or private keys in issues, logs or commits.
