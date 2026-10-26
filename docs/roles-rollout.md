# Administrative role rollout and rollback

This runbook activates the fine-grained Identity roles defined in
`roles-and-permissions.md`. It does not authorize an unattended production
change. LOGIN01 remains unchanged until a maintenance window, a fresh rollback
and explicit approval exist.

## Change boundary

The release adds optional AD group mappings and request-time authorization. It
does not add or alter database tables. The existing `admin_group_dn` remains
the unrestricted administrator and recovery group. Leaving every new group DN
empty reproduces the previous single-group behavior.

No role is emitted in an OIDC token or stored in the admin cookie. Access roles,
Badge/PIN, Greeter, PKINIT, Kerberos and the AD-password fallback are outside
this change.

## Preflight

1. Confirm the release commit and CI result on `development` and `main` as
   required by the release process.
2. Read the active unit, binary version, configuration path and service status
   without changing them.
3. Confirm verified LDAPS and a successful Framework user read.
4. Confirm the current `admin_group_dn` and at least two tested members. Never
   print bind passwords, session keys or group membership containing personal
   data into the transcript.
5. Back up the active binary and configuration into a new root-only directory.
   Record SHA-256 hashes and modes. Although there is no schema migration, take
   the normal consistent database backup so the maintenance window has one
   complete recovery point.
6. Validate the candidate configuration offline. Group DNs must be exact and
   distinct; unconfigured roles remain empty.
7. Build and hash the candidate from the reviewed release commit. Do not build
   on LOGIN01.

## Staged activation

1. Install the candidate binary atomically while all new role group settings
   remain empty.
2. Restart only the Identity service and verify readiness, TLS, SQLite or
   PostgreSQL health, the journal and login with the existing administrator.
3. Verify that the existing administrator can still read and change users,
   badges/PINs, audit, OIDC clients/sessions and client status.
4. Create and populate AD role groups through the separately controlled AD
   administration process. Identity itself does not create or modify groups.
5. Configure one optional group DN per maintenance increment, restart Identity
   and test one member plus one non-member. Start with `identity_auditor`, then
   the operator groups.
6. For every role, test the allowed pages and a direct denied HTML and JSON
   write. A hidden button is not evidence of authorization.
7. Remove a test user's role while its cookie remains active. The next
   privileged request must return 403. Restore membership only after recording
   the result.
8. During a controlled directory-unavailability test, privileged requests must
   return 503 while logout remains possible. Do not interrupt the normal AD
   password recovery path on client systems.

## Acceptance

- full administrator retains every existing capability;
- Identity operator can manage users, badges and PINs but not audit, OIDC or
  clients;
- OIDC operator can manage clients and sessions but not identities or badges;
- client operator can read client/system status only;
- auditor can read the documented areas and sees no mutation controls;
- combined memberships produce the union of their permissions;
- role removal and LDAP errors fail closed without waiting for cookie expiry;
- successful mutations retain exactly one transactional audit event and denied
  mutations change no row;
- session cookies, HTML, logs and audit contain no group DN or role inventory;
- OIDC login and revocation, self-service AD-password login, Passkeys,
  Badge/PIN, Greeter password fallback, PKINIT and Kerberos smokes pass;
- service journal, database integrity and Access readiness remain healthy.

## Rollback

The preferred first rollback is configuration-only: clear all four optional
role group settings and restart Identity. This restores the legacy
single-administrator-group behavior while keeping the candidate binary.

If the binary must also be reverted:

1. stop Identity;
2. restore the previous binary and configuration from the new root-only
   rollback directory after verifying recorded hashes and modes;
3. start Identity and verify the existing administrator login, OIDC discovery
   and JWKS, Access readiness, self-service password login and database health;
4. repeat Badge/PIN, PKINIT, Kerberos and Greeter fallback smokes appropriate to
   the maintenance window.

No database restore is normally required because this feature has no migration
and stores no role state. Restore the database only if an independent database
failure occurred, following the existing database recovery runbook. Never
retain a permissive local role cache as a workaround for an LDAP outage.
