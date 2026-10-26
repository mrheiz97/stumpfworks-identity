# Time-limited emergency administration

Emergency administration is an opt-in break-glass path for Identity when the
configured directory is temporarily unavailable. It is disabled by default and
does not replace the normal AD-backed administrator login.

## Security contract

- Only a local operating-system administrator can issue, list or revoke grants
  with `identity-admin` and the root-readable Identity configuration.
- A grant lasts between 5 and 60 minutes (15 minutes by default), is accepted
  exactly once, and is stored only as a SHA-256 token hash.
- A successful exchange creates a separate `emergency-admin` cookie audience.
  The cookie contains a random session identifier; only its SHA-256 hash is
  stored. Every privileged request checks the unexpired, unrevoked database row.
- The session deliberately receives the existing full administrator permission
  set. It does not depend on LDAP after issuance, so it remains usable during a
  directory outage.
- Issuance, successful exchange, explicit revocation and logout revocation are
  transactional with their audit records on SQLite and PostgreSQL. Audit
  failure leaves the grant or session state unchanged.
- Tokens, token hashes and session hashes are never shown in listings, browser
  pages or audit details. The clear token is printed once at issuance.
- Rate limiting and generic browser errors avoid token-oracle behavior. Secure,
  HTTP-only, SameSite-strict cookies and the normal session-bound CSRF contract
  protect administrative writes.

The path does not alter AD password fallback, Badge/PIN, Greeter, Passkeys,
OIDC, PKINIT or Kerberos behavior.

## Configuration and use

Keep the feature disabled until a reviewed maintenance window:

```yaml
emergency_admin:
  enabled: false
```

After enabling it and restarting Identity, issue a short grant locally:

```bash
sudo identity-admin --config /etc/stumpfworks-badge/config.yaml \
  emergency-admin issue --minutes 15
```

Open `/emergency-login` over the normal verified HTTPS origin and enter the
one-time token. Do not paste the token into tickets, chat, shell history or
logs. The normal `/login` route remains unchanged.

Review or revoke current grants locally:

```bash
sudo identity-admin --config /etc/stumpfworks-badge/config.yaml emergency-admin list
sudo identity-admin --config /etc/stumpfworks-badge/config.yaml \
  emergency-admin revoke --id '<grant-id>'
```

Signing out revokes the current emergency session server-side. Expiry and an
operator revocation invalidate it on the next request.

## Rollout and rollback

1. Confirm the current Identity build, configuration, database backend, TLS
   health and a recent verified backup without changing production.
2. Create a stopped, consistent database copy plus binary and configuration
   rollback. Store them root-only.
3. Install the release and start once with `emergency_admin.enabled: false`.
   Verify schema migration, health, AD administrator login, OIDC, Passkeys,
   Badge/PIN, PKINIT and Kerberos smoke tests.
4. Enable only the emergency flag. Issue a five-minute test grant, exchange it,
   verify one audit event for issuance and login, then sign out and confirm the
   old cookie is rejected with exactly one revocation audit.
5. Test explicit revocation of an unused grant and automatic expiry. Never use
   a production token as test evidence.

For immediate rollback, set the flag to false and restart. The route then
returns 404 and existing emergency cookies cannot pass the guard. If binary
rollback is required, stop Identity and restore the previous binary and
configuration. The additive table can remain unused; restore the consistent
database copy only when migration rollback is explicitly required and reconcile
any later writes first.

Production activation requires a separate approved maintenance window. A
repository release alone neither enables nor installs this function.
