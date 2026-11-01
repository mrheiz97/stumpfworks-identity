# Certificate extraction preparation

Historical preparation record. The separately approved implementation is now
published as Framework v1.2.0 and adopted on Identity `development`; see
[certificate verifier migration](framework-certificate-migration.md) for actual
APIs, verification evidence, defensive compatibility decisions and rollback.
The proposal and sequencing below describe the original preparation baseline.
No production listener, CA, credential or deployment was changed.

## Evidence and existing capabilities

The pinned `github.com/mrheiz97/stumpfworks-framework v1.0.0` module was inspected
read-only. `directory/ldap.Config.Roots` already accepts `*x509.CertPool`; the
reader uses Go TLS with hostname verification and minimum TLS 1.2. Framework
OIDC/HTTP consumers accept HTTP clients. No exported general peer-certificate,
issued-device-material or CSR validation package exists in this pinned version.
Go `crypto/tls`, `crypto/x509`, `encoding/pem` and `crypto.Signer` remain the
cryptographic foundation; upstream extraction must compose them, not reimplement
chain building or introduce a second TLS/LDAP stack.

| Identity source | Reusable mechanism | Ownership after extraction |
| --- | --- | --- |
| `internal/deviceauth/certificate.go` | Consume a verified TLS leaf, compare peer/verified leaf, explicit clock, EKU and public projection | Generic evidence validation upstream; exact URI namespace/client-ID grammar stays in Identity |
| `internal/deviceclient/client.go:validateMaterialAt` | Chain/EKU/time validation, expected public-key binding and optional CA pin comparison | Pure verification upstream; trusted enrollment response and CA-rotation policy stay in Identity |
| `cmd/server/client_api.go` | Required client certs, explicit client CA pool, distinct listener | Listener activation, routing and addresses stay in Identity; use standard TLS configuration |
| `internal/deviceclient` / `internal/clientstatus` HTTP clients | TLS minimum, CA roots and key-pair loading | Candidate for later consolidation, after explicit root/limit/timeout/redirect contracts |
| `internal/server/device_certificates.go:parseDeviceCSR` | PEM parsing and CSR signature verification | Possible later pure helper; permitted ECDSA-P256 key and canonical SAN issuance are Identity policy |
| `internal/server/pkinit.go` | Standard CA parsing and certificate signing primitives | PKINIT realm, UPN/EKU extensions, grants and lifetimes remain separate and unchanged |

The read-only certificate UI is Identity policy: its 30-day warning, disabled
state and authentication mode do not belong in a general certificate library.
Likewise retain active-credential lookup, fingerprint/serial/SAN binding,
revocation, token-only/preferred/required decisions, no-downgrade behavior,
transactional audit, pending activation, enrollment replay, local private-key
generation, root-only bundles and rollback in Identity.

## First upstream slice: two pure verification boundaries

Proposed package area: a framework security/certificate package, name and public
API to be reviewed separately. No network, filesystem mutation, signing, database,
token, logging or Identity dependency is needed for the first slice.

1. **Verified peer evidence.** Accept a TLS connection state, explicit validation
   clock and caller-selected usage/profile. Require a non-nil peer leaf and
   matching leaf in a nonempty verified chain. Reject absent verification,
   malformed/nil inputs and invalid time/usage. Return public leaf information
   or an immutable bounded projection. Consuming `VerifiedChains` is not itself
   chain verification; callers must get the state from a verified Go TLS
   handshake. Never claim a manually populated state proves CA trust.
2. **Issued leaf verification.** Accept parsed certificate/chain, explicit roots,
   expected **public** key, clock and required EKU. Return verified public
   metadata. Keep PEM parsing/size bounds a separate explicit concern. A future
   helper must never require or return a private key merely to compare public
   keys. Do not infer trust roots from untrusted leaf contents, global defaults,
   URLs, AIA downloads or an omitted root argument.

Identity adapters retain the exact single URI SAN, absence of alternate DNS/IP/
mail identities, allowed device-ID grammar and ECDSA-P256 requirement. A generic
helper must not silently apply this device profile to server, LDAP, OIDC or
PKINIT certificates. CSR SANs do not authorize requested identities; the server
continues setting the canonical SAN from the registered client.

CA pinning compares certificate DER, not PEM whitespace. During renewal,
Identity supplies its installed device-CA pin; rotation remains a separately
approved workflow. Initial enrollment currently receives its device CA over
verified bootstrap HTTPS. This is an Identity trust decision, not permission
for a generic helper to trust an arbitrary response-supplied CA.

## Executable contracts prepared here

`internal/testutil/certificatecontract` contains **test support only**, imported
by Identity `_test.go` adapters. It supplies `RunPeer` and `RunIssued` with fresh
synthetic keys/certificates and a fixed clock. It does not implement runtime
verification, change framework behavior or introduce a shared production library.
The adapters currently exercise `deviceauth.FromTLS` and
`deviceclient.validateMaterialAt`. A later framework candidate must run the same
suites through new adapters, alongside all Identity-specific policy tests.

Covered contracts:

- Exact fingerprint/serial/URI projection, missing/unverified/different leaf,
  nil state/leaf/URI, explicit client EKU, no CN fallback, extra/duplicate SANs,
  zero serial, zero clock and exact validity boundaries.
- Real X509 chain verification of issued material, expected public-key mismatch,
  wrong CA pin, non-CA roots, malformed/trailing/multiple PEM blocks, wrong EKU,
  identity mismatch, expiry metadata mismatch, pinned DER equivalence and
  initial enrollment without a prior device-CA pin.
- Existing real mTLS handshake tests remain the evidence for trusted versus
  unknown CA/missing credential/wrong usage. Existing server/database tests
  remain the evidence for active credential, revocation, replay, mode and audit.

The local preparation adds explicit nil-input rejection to the peer adapter
and a deterministic clock seam to material validation. The production wrapper
still uses `time.Now()` and the same Identity checks. Invalid explicit validation
context is rejected. No valid certificate policy or deployment is switched.

Run:

```sh
go test ./internal/deviceauth ./internal/deviceclient -run FrameworkExtraction -count=1
go test ./...
go vet ./...
```

Use `scripts/test-local-postgres.ps1` for the established isolated Windows
PostgreSQL/TLS/OpenSSL verification. Linux CI additionally runs the race detector
and PostgreSQL 16. Keys are generated in memory or disposable test directories;
do not copy production certificates, bundles or CA private keys into fixtures.

## Compatibility decisions that must not be hidden in extraction

| Boundary | Current contract / decision |
| --- | --- |
| Certificate `NotAfter` | Go X509 and `FromTLS` include the exact boundary; retain this characterization |
| Active database credential | Requires `expires_at > now`; actual device authorization is exclusive at expiry |
| UI expiry | Exclusive and warns within 30 days; display policy stays local |
| EKU | Explicit ClientAuth is required; mixed EKUs are not newly prohibited by this preparation |
| URI/SAN | Exact Identity namespace and one URI, no alternate identities; not a universal X509 rule |
| PEM | Current material adapter accepts surrounding whitespace; Go PEM decoding can skip leading non-PEM text. A stricter future parser is a reviewed compatibility change, not a mechanical move |
| CA file handling | Device HTTP client bounds CA PEM at 1 MiB; status client currently lacks that same bound. Do not silently unify these wrappers |
| Trust roots | Current HTTP clients append an explicit CA to system roots; a device listener uses an explicit dedicated client CA pool. Preserve this distinction |
| Timeouts | Device HTTP client uses 15 seconds, status client 10 seconds, update worker overrides to 2 minutes |
| Redirects | Update worker prohibits redirects; existing enrollment/status wrappers have different behavior. Preserve caller ownership until separately reviewed |
| Errors | Framework errors must be bounded/sanitized; no PEM, private keys, raw request, token, subject or arbitrary transport output in logs/metrics |

Nil checks are a defensive preparation for reusable APIs; they do not mean Go's
TLS stack normally supplies nil peer certificates. The material test adapter
still receives a private key because that is Identity's current interface; it
is deliberately not the proposed framework signature.

## Handoff and migration sequence

1. Obtain explicit scope for changing the separate framework. Review the two
   pure APIs, error model, size limits, explicit clock/root/usage rules and
   portability. Copy only the portable conformance fixtures/adapters needed for
   that package; do not move Identity database or provisioning code.
2. Implement and release the approved framework slice there. Its tests must
   prove unrelated namespaces can use the helper without importing Identity,
   while strict Identity profile tests still reject foreign/duplicate SANs.
3. In Identity, pin a specific reviewed framework release. Run old and candidate
   implementations against the same synthetic valid/invalid inputs and compare
   public results and rejection classes. Run the complete SQLite/PostgreSQL,
   TLS/mTLS, enrollment/renewal, pinning, rollback, OIDC and PKINIT contracts.
4. Replace only the thin verification boundary. Keep namespace/algorithm/CA and
   lifecycle policy in Identity. Remove superseded local mechanism only after
   parity; do not maintain two active verification paths or a silent fallback.
5. Verify `go list -deps` for production commands excludes the test kit and any
   Identity import from the framework. No database migration is expected.
6. Prepare exact binary/hash/config rollback and perform normal release/CI.
   Production rollout is separate, with current preflight and maintenance
   approval. Reverting the dependency/adapter commit and rebuilding restores
   the prior verifier; deployed binary rollback remains independently verified.

This preparation completes the investigation/handoff scope. It does not authorize
the upstream implementation, dependency update or production migration.
