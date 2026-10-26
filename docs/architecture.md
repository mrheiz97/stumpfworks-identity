# Architecture

## Components

`LOGIN01` runs the Go HTTPS server, SQLite identity database, administrator UI, PIN self-service and PKINIT CA. `DC01` is the Samba AD domain controller and KDC. `WYSE01` is an AD member running LightDM, the native GTK3 greeter, camera helper and PAM helper. `FILE01` is an AD member providing Kerberos-protected SMB shares.

The existing Winbind/PAM membership on WYSE01 remains authoritative. SWBA adds one isolated `pam_exec` rule before the normal password stack; it does not replace the domain join or fallback.

## Badge login

1. The camera reads `SWBADGE:1:<BADGE_ID>:<TOKEN>`.
2. The greeter sends badge and PIN to LOGIN01 over verified HTTPS.
3. LOGIN01 validates token hash, badge state, PIN hash, rate limit and client ID.
4. It returns a random grant valid for 30 seconds, one use and one client.
5. The PAM helper consumes and deletes the runtime grant.
6. LOGIN01 exchanges it for a ten-minute user certificate and key.
7. The helper performs PKINIT against DC01 and writes `/tmp/krb5cc_<UID>` as the user with mode `0600`.
8. `pam_mount` uses `sec=krb5,cruid=<UID>` for the personal and public FILE01 shares.

The result is a real user TGT. No synthetic or stored AD password is involved.

## Web authentication

Administrator sessions require current recursive membership in at least one
configured Identity role group. The original administrator group retains full
access; optional Identity, OIDC and client operators plus an auditor receive
only the server-side permissions documented in
[`roles-and-permissions.md`](roles-and-permissions.md). Membership is resolved
again for every privileged request and fails closed when the directory is
unavailable. Roles and group DNs are not stored in the browser cookie or
emitted as OIDC claims.

An optional break-glass path is isolated in a separate `emergency-admin`
session audience. A root-only local command issues a bounded, single-use random
token whose hash is stored. Its exchange creates a separately hashed,
server-side session that is checked on every request and grants the legacy full
administrator permission set without consulting LDAP. Issuance, exchange and
revocation are atomic with their audit records. The route is absent unless the
feature is explicitly enabled.

Self-service accepts a valid AD user but can update only that identity's SWBA PIN and read a bounded list of active badges selected by the authenticated local user ID. Signed session tokens carry distinct `admin` and `self-service` audiences and cannot be exchanged. Browser writes use secure, HTTP-only, SameSite strict cookies and CSRF tokens. Self-service expires after 15 minutes.

Lost-badge self-service revocation is constrained again inside the database transaction by both badge ID and authenticated user ID. It never accepts a username or owner ID from form data and never returns whether a foreign badge exists.

Self-service login history is selected server-side from the signed session username and bounded to 20 badge-authentication events. The dedicated projection omits IP address and free-form audit details by construction and does not return unrelated event types or another username's records.

Replacement is a two-stage operation: the administrator atomically revokes the old active badge and issues a disabled badge marked only as pending activation. The assigned user must then present its one-time payload in self-service. Ownership, pending state and token hash must all match before activation; a lost or normally revoked badge is never eligible.

Self-service cookies remain signed and short-lived but now also reference a random server-side session record. Every request verifies both layers. Users can list their own active records and revoke all other sessions; deployment of this migration intentionally invalidates older untracked self-service cookies.

OIDC authorization codes remain short-lived and one-time. Their exchange now
creates a server-side OIDC session and an opaque access token whose cleartext
is returned once and whose SHA-256 hash is the only persisted token material.
The ID token carries the random `sid`. Confidential clients can introspect or
revoke only their own access tokens, while administrators can review bounded
session metadata and revoke by `sid`. Token issuance and revocation are each
atomic with their required audit record on SQLite and PostgreSQL.

## Trust boundaries

- Homelab TLS CA: LOGIN01 HTTPS
- PKINIT CA: short-lived user and KDC certificates
- Samba AD: users, groups, Kerberos and machine trust
- SQLite: mappings, hashes and audit metadata
- Runtime grant file: one-time greeter-to-PAM handoff

Private CA keys remain on LOGIN01. Cleartext PINs and badge tokens are never persisted.

## Availability

Password fallback remains available if badge authentication fails and AD is reachable. LOGIN01 and Samba services start at boot. Daily timers check certificate expiry; LOGIN01 also creates a consistent online SQLite backup.
