# Identity observability

Status: opt-in implementation contract. Metrics are disabled by default and a
production scrape requires its own maintenance window and rollback.

## Privacy and cardinality contract

The `/metrics` endpoint may expose only fixed component, outcome, module,
backend, object-kind, client-state, certificate and backup labels. It must
never expose usernames, badge codes or tokens, OIDC subjects or tokens,
Passkey identifiers, IP addresses, client IDs, versions, group DNs, file paths,
free-form audit details or error strings. Unknown routes collapse to
`unmatched`; status codes collapse to six fixed outcomes.

Identity reuses Framework v1.0.0 for HTTP route/status latency, Framework LDAP
lookup outcomes and PostgreSQL pool statistics. Identity owns only its bounded
application metrics:

- `sw_identity_info` and `sw_identity_start_time_seconds`;
- `sw_identity_module_enabled`;
- `sw_identity_operations_total` and
  `sw_identity_operation_duration_seconds`;
- `sw_identity_audit_write_failures_total` for explicit best-effort audit
  writes; transactional audit failures also appear as failed operations;
- `sw_identity_objects` and `sw_identity_clients`;
- `sw_identity_certificate_not_after_seconds`;
- `sw_identity_backup_timestamp_seconds` and
  `sw_identity_maintenance_mode`;
- `sw_identity_collection_errors_total`.

Scrape-time database reads have a two-second deadline. Failures omit the stale
gauge family and increment a bounded collector counter. They never make the
application unavailable or reveal the underlying error.

## Configuration

```yaml
metrics:
  enabled: true
  token_file: "/etc/stumpfworks-badge/metrics-token"
  backup_path: "/var/backups/stumpfworks-badge/latest.db"
  maintenance_file: "/run/stumpfworks-badge/maintenance"
```

The token file must be root-managed, readable by the service group, mode 0640
or stricter, and contain at least 32 random bytes. Never place the token in Git,
Prometheus YAML, a command line or diagnostic output. The backup path should be
a stable symlink or file updated only after a successful, verified backup. The
maintenance marker is present only while alerts should be suppressed for an
approved maintenance operation.

The endpoint accepts only `GET` with `Authorization: Bearer ...`. Missing or
wrong credentials receive a generic response. HTTPS and the Homelab CA remain
mandatory; `insecure_skip_verify` is prohibited.

## Prometheus and Grafana

Versioned examples are in `deploy/prometheus/identity-scrape.yml`,
`deploy/prometheus/identity-rules.yml` and
`deploy/grafana/identity-dashboard.json`. Replace example targets and paths
locally, then run:

```sh
promtool check config /etc/prometheus/prometheus.yml
promtool check rules /etc/prometheus/rules/identity.yml
```

Prometheus, Alertmanager and Grafana remain separate infrastructure. Identity
does not embed them. Alert delivery is intentionally independent of ntfy,
which is not part of this project's roadmap.

## Required acceptance

1. Run unit, race, privacy and 500-path cardinality tests.
2. Verify unauthorized and wrong-token scrapes are generic and authorized
   exposition parses with `promtool`.
3. Confirm no forbidden marker from synthetic usernames, IDs, tokens, IPs,
   DNs, versions or errors appears in exposition.
4. Exercise HTTP, LDAP, SQLite/PostgreSQL collector failure, stale client,
   certificate and backup thresholds.
5. Start with a read-only Prometheus scrape and no alert delivery; compare
   series count and scrape duration under load.
6. Import the dashboard, then test each alert with bounded synthetic state and
   maintenance suppression.
7. Only then enable production alert delivery.

## Production rollout and rollback

Before activation, record service/config/binary hashes and create a stopped,
consistent root-only rollback including SQLite and the metrics token. Enable
only the metrics block; do not modify AD login, Badge/PIN, Greeter, Passkeys,
OIDC, PKINIT or Kerberos. Verify Health, OIDC, LDAP, SQLite, journal and an
authorized scrape. Rollback restores the previous binary and configuration,
removes the token and maintenance marker, reloads the service and verifies the
same preserved paths. Prometheus configuration has its own independent backup
and reload rollback.
