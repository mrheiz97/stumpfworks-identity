# Framework certificate verifier migration

Status: implemented on Identity `development`, using the published, signed
[Framework v1.2.0](https://github.com/mrheiz97/stumpfworks-framework/releases/tag/v1.2.0).
No Identity release or deployment is part of this change. No listener, client,
CA, credential, authentication mode, schema or production configuration changes.

## Release and dependency evidence

Framework release commit: `ee5e1f9e6cd603e585a5f2cb4a365f6d05a4e680`.
The release passed feature/develop/main CI and
[release workflow 41325662101](https://github.com/mrheiz97/stumpfworks-framework/actions/runs/41325662101).
GitHub verified the annotated SSH-signed `v1.2.0` tag. Published source archive
and CycloneDX SBOM match `SHA256SUMS`; GitHub attestations verify against the
repository's tagged release workflow. Framework `develop` was fast-forwarded
to the reviewed release commit without force-pushing.

Identity pins `github.com/mrheiz97/stumpfworks-framework v1.2.0` through normal
Go module checksums, with no local replacement. Minimum Go is **1.26.10**:
the framework requires the X509 intermediate-certificate distrust fix
[GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809). Keep this patched toolchain
when rebuilding a rollback; do not restore the former Go 1.26.8 minimum.

## Runtime boundary

| Caller | Framework mechanism | Identity policy retained |
| --- | --- | --- |
| `deviceauth.FromTLS` | `certificates.VerifiedPeer`: matching verified TLS leaf, explicit time/ClientAuth, public metadata | Exact single `urn:stumpfworks:identity:client:` URI, ASCII client-ID grammar, no other SAN identities, local error mapping |
| `deviceclient.validateMaterialAt` | `certificates.VerifyIssued`: explicit-root X509 verification, ClientAuth/time, expected public-key binding, optional root DER pin | Response bounds/PEM shape, bootstrap CA trust decision, ECDSA-P256, exact URI, expiry metadata, private-key serialization and bundle handling |

`VerifiedPeer` consumes Go TLS verification evidence; it does not authenticate a
hand-built connection state or rebuild the chain. Dedicated listener CA pools,
handshake verification and routing remain local. The framework receives only a
PKIX public key, never the client's private key. Renewal supplies the installed
device CA as a pin; bootstrap's verified HTTPS response remains the initial
trust boundary. There is no implicit CA rotation or system-root fallback here.

Database active-credential lookup, fingerprint/serial/SAN binding, revocation,
token modes and no-downgrade rules, pending activation, transactional audit,
issuance, enrollment/renewal, local bundle rollback, PKINIT, LDAP, HTTP wrappers
and the read-only certificate overview retain their existing ownership.
There is one runtime verifier path; rejection never retries the old verifier.

## Compatibility and deliberate defensive limits

- X509 validity includes `NotBefore` and `NotAfter`; actual active credentials
  still require database `expires_at > now`. UI expiry remains exclusive.
- Explicit ClientAuth is required; mixed explicit ClientAuth/ServerAuth remains
  accepted. Exact URI and absence of DNS/mail/IP SANs remain consumer policy.
- PEM whitespace and the existing decoder's leading-text behavior are retained.
  Root pinning compares certificate DER, independent of PEM whitespace.
- Framework derives metadata from signed DER, ignoring modified parsed fields.
  Identity also retains defensive rejection of nil parsed URI entries. Synthetic
  mutation tests document this; real TLS provides parsed signed certificates.
- Framework bounds each DER certificate at 1 MiB and SAN projections at 128
  entries. Identity's existing 128 KiB response limit and single-SAN policy are
  stricter for eligible device material.
- Positive leaf serials are now required during material validation as well as
  peer authorization. The former material-only verifier accepted zero; Identity's
  issuer and credential store already exclude it. A dedicated regression test
  records this intentional fail-closed difference outside the parity contract.
- Errors remain bounded and contain no PEM, keys, tokens or raw certificate
  identities. Framework errors are mapped at the existing Identity boundary.

## Verification

Frozen baseline verifiers live only in `_test.go` files. Portable contracts
compare old/new accept/reject outcomes, peer projections and complete returned
material using fresh synthetic fixtures. They cover missing/unverified/nil
evidence, leaf mismatch, explicit EKU, SAN/namespace policy, validity boundaries,
key mismatch, malformed PEM, wrong/non-CA roots, wrong pin and expiry metadata.
Dedicated tests cover unsigned parsed identity changes and zero serials.

```sh
go test -count=1 ./internal/deviceauth ./internal/deviceclient
go test -count=1 ./...
go vet ./...
go mod verify
go list -deps ./cmd/server ./cmd/client-device
```

Use `scripts/test-local-postgres.ps1` for disposable PostgreSQL 17, real
import/reconciliation/custom-dump restore, TLS/OpenSSL and the full local suite.
It disables test caching because each cluster reuses the same connection URL.
Linux CI adds race detection, PostgreSQL 16, Prometheus, Python and shell checks.
Production dependency lists must contain `security/certificates` and exclude
`internal/testutil/certificatecontract`; frozen verifiers never compile into
production commands. No production data or keys are used in these tests.

## Prepared and checked rollback

Baseline: Identity `4f4fc2586f36c189779683d36102f46da8676274` on development,
Framework v1.0.0. Before changing the dependency, an exact `git archive` was
extracted under ignored `dist/identity-framework-rollback-4f4fc25/source`.
Linux-amd64 server and device installer candidates were built from that source
with `GOTOOLCHAIN=go1.26.10`, `CGO_ENABLED=0`, `-trimpath -buildvcs=false`.
The archived source's full synthetic suite and vet were also exercised with
the patched toolchain. Archive and binaries have a local SHA-256 manifest.
These are local development recovery artifacts, not an installed production
backup; they contain no production configuration, database or credentials.

For a development source rollback, restore only these files from the baseline
in a clean recovery checkout (or revert the migration commit):

```sh
git restore --source=4f4fc2586f36c189779683d36102f46da8676274 -- \
  internal/deviceauth/certificate.go internal/deviceclient/client.go go.mod go.sum
go mod edit -go=1.26.10
go mod tidy
```

The baseline `_test.go` contracts can be restored alongside the runtime files;
new migration-only defensive tests characterize v1.2.0 and should be reverted
with its migration. Keep independent later application changes when recovering.
Then rerun module verification, the full synthetic suite, vet, Linux race CI,
and rebuild both binaries with recorded SHA-256 hashes. Verify rollback artifact
hashes before using local candidates. Never force-reset shared development or
move the published Framework tag.

No schema or certificate conversion is needed. Preserve installed CA, bundles,
pending/active records and token modes; do not use SQL or re-enrollment to undo
this library migration. Any later deployment requires its own fresh consistent
binary/configuration/database backup and maintenance authorization. If that
deployment fails, use its verified binary rollback and existing bundle recovery;
this document grants no production action.
