# StumpfWorks Identity

> Native QR badge and PIN authentication for Linux clients, backed by Samba Active Directory, Kerberos PKINIT and short-lived credentials.

![StumpfWorks Identity native LightDM greeter](docs/assets/swba-greeter.png)

StumpfWorks Identity turns a managed Linux workstation into a badge-enabled domain client. A user scans a revocable QR badge, enters a personal PIN and receives a real Active Directory Kerberos TGT. Normal AD username/password login remains available as a fallback.

## Why StumpfWorks Identity?

- Native GTK3 LightDM greeter instead of a browser kiosk
- QR badge plus personal PIN without storing the AD password
- 30-second, single-use and client-bound login grants
- Ten-minute user certificates issued by a dedicated PKINIT CA
- Real Kerberos TGTs and `sec=krb5` CIFS mounts
- LAN/WLAN status and pre-login Wi-Fi selection
- Responsive administration and user PIN self-service
- Hashed badge tokens, Argon2id PINs, rate limiting and secret-free audit logs
- Guided, role-based installation with rollback files

## Authentication flow

```mermaid
flowchart LR
    B[QR badge + PIN] --> G[Native LightDM greeter]
    G -->|HTTPS| L[Login server]
    L -->|one-time grant| H[PAM helper]
    H -->|short-lived certificate| K[Samba AD PKINIT]
    K --> T[Kerberos TGT]
    T --> F[CIFS mounts]
```

The QR payload is `SWBADGE:1:<BADGE_ID>:<TOKEN>`. Badge tokens, PINs, passwords, private keys and grants must never be committed or logged.

## Components

| Component | Purpose |
|---|---|
| Login server | HTTPS API, administration, self-service, audit and certificate issuance |
| Native greeter | Camera scan, PIN entry, password fallback and network selection |
| PAM helper | Exchanges a one-time grant for a certificate and obtains the user TGT |
| Samba AD | Verifies PKINIT and issues Kerberos tickets |
| File server | Provides Kerberos-authenticated personal and shared CIFS mounts |

## Quick start

Requirements and security boundaries are documented in [Installation](docs/installation.md). The guided installer supports the login server, Linux clients and domain-controller certificate monitoring:

```bash
sudo ./scripts/install-interactive.sh
```

All committed configuration uses the reserved example domain `example.test`. Copy the templates to local ignored configuration files and supply your own realm, hostnames, CA and service-account details. The installer deliberately does not automate the initial Samba PKINIT configuration because that change affects a production domain controller.

Example interfaces after deployment:

- Administration: `https://login01.example.test:8080/`
- PIN self-service: `https://login01.example.test:8080/self-service`

Always install the deployment CA correctly. Never bypass TLS verification.

## Security model

- Badge tokens are stored as hashes and never written to audit logs.
- PINs use Argon2id and are protected by rate limiting.
- Login grants are random, expire after 30 seconds, are single-use and bound to a client ID.
- PKINIT certificates expire after ten minutes.
- Administrative and self-service sessions use separate signed audiences.
- AD credentials are verified over LDAPS and are never persisted.
- Normal username/password login remains available as a recovery path.

See [Security](docs/security.md) for trust boundaries, threat assumptions and operational safeguards.

## Verification

```bash
go test ./...
python3 -m py_compile cmd/native-greeter/sw-badge-native-greeter.py
python3 -m py_compile scripts/swbadge-sqlite-backup.py
sh -n scripts/swbadge-cert-check.sh
git diff --check
```

The PKINIT test invokes the OpenSSL CLI. Run the complete suite on Linux when OpenSSL is unavailable on Windows.

## Project layout

```text
cmd/                 Server, greeter, agent and PAM-helper entry points
internal/            Authentication, directory, PIN and server packages
deploy/              systemd, PAM, LightDM, client and PKINIT templates
scripts/             Installer, camera, backup and maintenance tools
docs/                Architecture, API, security and operations guides
```

## Documentation

- [StumpfWorks Access OIDC integration](docs/oidc-access.md)

- [Architecture](docs/architecture.md)
- [Installation](docs/installation.md)
- [Security model](docs/security.md)
- [Operations and recovery](docs/operations.md)
- [Development](docs/development.md)
- [API](docs/api.md)
- [Changelog](CHANGELOG.md)

## Branching and releases

- `main` contains only tested, release-ready code.
- `development` is the integration branch for new work.
- Feature and fix branches start from `development` and return through reviewed merges.
- A merge into `main` requires local tests and an end-to-end test on the target systems.

The v1.0 boundary is a stable identity and authentication platform. Identity administration is intentionally deferred to a later release and requires a dedicated least-privilege AD account, privileged-group protection, explicit confirmation, complete auditing and rollback.

## License

MIT License © StumpfWorks.
