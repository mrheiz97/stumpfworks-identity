# Administrative roles and permissions

Status: design contract for P3.2. This document does not enable new roles or
change a production system.

## Goals and compatibility

Identity currently grants every member of `directory.admin_group_dn` complete
administrative access. Fine-grained roles extend this boundary without
weakening it:

- the existing administrator group remains the break-glass-compatible
  `identity-admin` role and retains every permission;
- an installation that configures no additional role groups behaves exactly as
  it does today;
- AD password fallback, Badge/PIN, Greeter, PKINIT, Kerberos, OIDC and
  self-service keep their existing authentication and authorization contracts;
- Identity roles are never emitted as OIDC claims and do not replace Access
  roles or physical-access policies;
- `identity-admin`, the local command-line tool, remains an operating-system
  privilege boundary and is not authorized by browser roles.

## Roles

Each optional role maps to one distinct AD group DN. Membership is recursive,
using the same Active Directory matching rule already used for administrators.
Empty group settings disable the corresponding role.

| Role | Purpose |
| --- | --- |
| `identity-admin` | Existing unrestricted administrator and emergency role |
| `identity-operator` | Import users and manage Badge/PIN credentials |
| `oidc-operator` | Manage OIDC clients and revoke OIDC sessions |
| `client-operator` | Inspect managed clients and system/client health |
| `identity-auditor` | Read operational state and audit history without changing state |

A user may hold multiple roles. Permissions are the union of all current
roles. The full administrator role always implies every permission and cannot
be narrowed through additional configuration.

## Permission matrix

The server enforces permissions by HTTP route and method. Hiding a navigation
item or form is only a usability feature and never the security boundary.

| Area | Read permission | Change permission | Roles |
| --- | --- | --- | --- |
| Dashboard | `dashboard.read` | n/a | every administrative role |
| Users and directory | `identity.read` | `identity.write` | admin; operator read/write; auditor read |
| Badges and PINs | `credentials.read` | `credentials.write` | admin; operator read/write; auditor read |
| Audit log | `audit.read` | n/a | admin; auditor |
| OIDC clients | `oidc.read` | `oidc.write` | admin; OIDC operator read/write; auditor read |
| OIDC sessions | `oidc.sessions.read` | `oidc.sessions.revoke` | admin; OIDC operator read/revoke; auditor read |
| Managed clients | `clients.read` | n/a in the current UI | admin; client operator; auditor |
| System status | `system.read` | n/a | every administrative role |

The existing JSON administration endpoints use the same permissions as their
HTML equivalents. Badge authentication, PKINIT, client status submission,
OIDC protocol endpoints and self-service are not administrative endpoints and
must not be placed behind these roles.

## Authentication and request authorization

1. Login verifies the supplied AD password and requires membership in at least
   one configured Identity role group.
2. The signed `swbadge_admin` cookie continues to contain only its audience,
   username and expiry. Group DNs, roles and permissions are not stored in the
   browser.
3. Before serving an administrative request, Identity resolves the user's
   current recursive group memberships through the service-bound directory
   connection and derives permissions locally.
4. A directory error, an unknown role, or no remaining role fails closed. A
   removed membership therefore cannot remain valid for the full cookie
   lifetime.
5. Mutating requests still require the existing CSRF proof after successful
   authorization. Authorization never weakens CSRF or rate limiting.
6. Authorization denials return HTTP 403. Unauthenticated or invalid sessions
   keep the existing redirect to `/login`.

A short in-memory cache may be added only after measurement. Its maximum age
must be explicit and bounded, it must never outlive the session, and directory
errors must not extend stale authorization. The first implementation performs
the current-membership check without such a cache.

## Audit and data minimization

Successful state changes retain their existing transactional audit event. A
role check must not introduce a second success event or move an audit write
outside the data transaction.

Denied administrative requests may use the existing best-effort rejection
audit boundary. Such an event contains only the event type, username, requested
permission, HTTP method, bounded route identifier and source IP. Passwords,
cookies, CSRF values, group DNs, secrets, token material and directory query
details must never be logged or audited.

## Configuration and rollout

The existing setting remains mandatory for protected deployments:

```yaml
directory:
  admin_group_dn: "CN=SWBadge-Admins,CN=Users,DC=example,DC=test"
```

Optional group settings are introduced separately:

```yaml
directory:
  identity_operator_group_dn: ""
  oidc_operator_group_dn: ""
  client_operator_group_dn: ""
  identity_auditor_group_dn: ""
```

Environment-variable equivalents follow the existing
`SWBADGE_DIRECTORY_*_GROUP_DN` naming scheme. Configuration must reject a role
group DN that duplicates another configured role group DN, except that an
explicitly documented migration mode may temporarily allow overlap. The
initial implementation has no overlap mode and fails startup instead.

Rollout is staged and reversible:

1. add authorization types, LDAP membership resolution and unit/contract tests;
2. add route enforcement and permission-aware templates with all optional
   groups still empty;
3. prove the unchanged administrator path and all existing login smokes;
4. create and populate one AD role group at a time outside Identity;
5. enable one group setting per maintenance window after a configuration and
   binary rollback exists;
6. verify membership removal, LDAP outage, session continuation, audit and all
   preserved authentication paths before enabling the next role.

## Framework boundary

Identity continues to use the Framework LDAP transport, TLS trust and lookup
facilities. Role names, AD group mapping, the permission matrix, route policy,
Identity audit events and failback rules remain in this repository.

After the contract is stable in production, only generic primitives are
candidates for the StumpfWorks Framework: normalized recursive group-membership
lookup, permission-set helpers and reusable HTTP authorization middleware.
Identity-specific policy must not be moved into the Framework.

## Required tests before production

- legacy administrator can read and change every existing administrative area;
- each role can use exactly the routes in the matrix and receives 403 elsewhere;
- combined roles produce the union, never an accidental intersection or
  privilege escalation;
- nested AD membership works and similarly named groups do not match;
- removal from all configured groups invalidates the next privileged request;
- LDAP timeout, TLS failure and malformed membership response fail closed;
- cookie tampering, wrong audience, expiry, CSRF failure and direct JSON calls
  remain rejected;
- denied writes produce no database mutation and no success audit;
- successful writes retain one transactional success audit on SQLite and
  PostgreSQL;
- concurrent membership changes and requests do not grant stale permissions;
- OIDC, AD-password recovery, Badge/PIN, Greeter, PKINIT and Kerberos smoke
  tests remain green;
- rollback to the previous binary and configuration restores the single-admin-
  group behavior without a database migration.
