# Signed client updates

`sw-badge-client-updater` supports mutually exclusive verification and installation modes. Installation is restricted to signed packages, compiled-in component targets, new absolute staging and rollback directories, atomic file replacement and mandatory service health checks.

An update ZIP contains exactly:

- `manifest.json`
- `manifest.sig`, a base64 Ed25519 signature over the exact manifest bytes
- one `payload/<component>` entry for every manifest file

The schema records release version, channel (`development` or `stable`), target OS/architecture, minimum client version, creation time, and the exact size and SHA-256 digest of every component. Component names come from a fixed allowlist; paths, commands and installation destinations cannot be supplied by a package.

`update-packager` creates Ed25519 key pairs and signed packages. Development and stable releases must use separate keys. The private key must live outside the repository on a restricted release workstation and must never be copied to LOGIN01 or a client. The public key is the only key installed on clients. Key and package output paths are create-only and existing files are never overwritten.

Example development key generation and package creation:

```bash
update-packager --generate-key \
  --private-key /secure/offline/development-update-ed25519.key \
  --public-key /secure/offline/development-update-ed25519.pub

update-packager \
  --private-key /secure/offline/development-update-ed25519.key \
  --output stumpfworks-client-1.2.0-linux-amd64.zip \
  --release 1.2.0 \
  --channel development \
  --architecture linux-amd64 \
  --minimum-version 1.2.0-dev \
  --component sw-badge-client-status=./sw-badge-client-status
```

Verification rejects unknown manifest fields, trailing JSON, duplicate or unlisted ZIP entries, unsafe paths, unsupported components, malformed versions, wrong architecture, excessive sizes, invalid hashes and invalid signatures. The release public key is provided separately as a base64 Ed25519 key. A private release key must never be installed on LOGIN01 or a client and must never be committed.

Example dry run:

```bash
sw-badge-client-updater \
  --dry-run \
  --package stumpfworks-client-1.2.1-linux-amd64.zip \
  --public-key /etc/stumpfworks-badge/client-update.pub
```

An optional `--stage-dir` extracts verified components into a new mode-restricted directory and writes `stage-plan.json`. Existing directories are never overwritten. The plan contains only fixed component-to-target mappings compiled into the updater, expected modes and whether a future installation would require a LightDM restart. Payload hashes are checked again while staging to close the verification-to-extraction gap. Staging never writes to an installation target.

Rollback preparation uses the fixed stage plan to copy only known existing target files into a new mode `0700` directory. Each saved file is mode `0600`, hashed, size-limited and recorded in `rollback.json`; targets that did not previously exist are recorded explicitly. Symlinks, special files, duplicate components, changed target mappings and existing rollback directories are rejected.

The internal restore implementation validates the complete manifest and every backup before changing any target. Existing files are restored through same-directory atomic replacements; files recorded as previously absent are removed. A restore can be rerun safely after an injected mid-restore failure. Installation failures and failed health gates invoke this restore automatically; there is deliberately no broad manual restore command that accepts arbitrary targets.

The installation transaction revalidates the complete staged payload, creates the rollback snapshot, prepares replacement files and atomically replaces fixed targets. Any preparation or application error invokes rollback automatically. A successful transaction requires a non-optional post-install health callback; a failed health result restores the old files after proving that the new files were visible to the check. Failure-injection tests also prove that a tampered stage is rejected before a rollback directory or target change is created.

Before the first target replacement, the updater atomically writes a root-only
transaction marker under `/var/lib/stumpfworks-badge`. The marker contains only
the release version, start time and absolute rollback directory; it contains no
credentials, payload data or command output. It is removed only after the
post-install health gate succeeds or a controlled failure has been restored.

`swbadge-client-status.service` invokes `sw-badge-client-updater
--recover-pending` before its normal report. If a process crash or power loss
left a marker behind, recovery validates the bounded marker, the complete
rollback manifest, all hashes and every fixed component target before changing
any file. It then restores the previous files, records a bounded failed update
state, starts the status timer if interrupted maintenance left it stopped,
verifies LightDM, and allows the normal status report to
continue. A failed recovery keeps the marker so the next service run can retry;
it never accepts target paths or commands from the marker. The updater binary
itself is an allowed signed component so existing clients can receive this
recovery behavior through the normal package format.

Concrete orchestration requires an explicit maintenance-window flag for greeter components. Non-greeter updates reload systemd only when unit files changed, submit an immediate client-status report when relevant, require the status timer to remain active and always require LightDM to remain active. Command failures propagate into the mandatory health gate and therefore trigger automatic rollback. These commands are covered by a simulated runner and are now used by the guarded CLI installation mode.

Installation requires fresh, distinct absolute directories. Neither directory may already exist:

```bash
sw-badge-client-updater \
  --install \
  --package stumpfworks-client-1.2.1-linux-amd64.zip \
  --public-key /etc/stumpfworks-badge/client-update.pub \
  --stage-dir /var/lib/stumpfworks-badge/updates/1.2.1-stage \
  --rollback-dir /var/backups/stumpfworks-badge/client-1.2.1
```

After installation, one read-only acceptance command now joins the release,
installed-state and restore evidence:

```bash
sw-badge-client-updater \
  --accept \
  --package stumpfworks-client-1.4.1-linux-amd64.zip \
  --public-key /etc/stumpfworks-badge/update-development.pub \
  --rollback-dir /var/backups/stumpfworks-badge/client-1.4.1
```

Acceptance verifies the Ed25519 signature and complete package, requires every
installed component to match the signed size, SHA-256 digest, fixed target and
Linux mode, and verifies the complete rollback manifest and every saved file.
The rollback release and component set must exactly match the accepted package.
Rollback directories must be mode `0700`; manifests and saved files must use
mode `0600`.
It then submits one normal status report when the package contains status
components and checks the status timer, LightDM and, for greeter releases, the
persistent VNC service. It neither installs nor restores files and never
restarts LightDM or VNC. The rollback directory remains restricted to
`/var/backups/stumpfworks-badge`.

The install mode stages and revalidates the package, creates the complete rollback snapshot before replacing files, and runs component-aware systemd checks. If installation or health validation fails, all files are restored and systemd health recovery runs against the restored state. A greeter component is rejected unless `--allow-lightdm-maintenance` is supplied; with that explicit authorization LightDM is restarted after installation and again after any automatic rollback. The persistent `swbadge-vnc.service` is rebound to the new X display with `try-restart`; an inactive service remains inactive. The normal password fallback must be checked during a separately approved production maintenance test.

Before the mandatory service report, the updater atomically writes `/var/lib/stumpfworks-badge/update-state.json`. The bounded state contains only the target release, `success` or `failed`, the UTC timestamp and whether the rollback snapshot exists. The client status reporter sends this optional object with its normal health report. LOGIN01 rejects malformed versions, unknown results and unreasonable timestamps, stores the last accepted outcome and displays it in the registered-client overview. Clients without updater state remain compatible and show “No update reported”.

The guided client installer installs the updater and the selected Ed25519 public key as `/etc/stumpfworks-badge/client-update.pub`. It never asks for or copies a private signing key. The installer verifies the updater version, NetworkManager availability and an immediate status report before optionally restarting LightDM.

The first real WYSE01 update test on 27 August 2026 installed only `sw-badge-client-status` from `1.2.0-dev` to signed development release `1.2.0`. The installed payload hash matched the signed artifact, the timer and LightDM remained active, LOGIN01 received version `1.2.0` with all health fields `ok`, and the real rollback snapshot restored successfully in a local simulated root without changing WYSE01.

On 20 October 2026, crash recovery was accepted on WYSE01 with a dedicated
rollback. A controlled interruption marker was activated after the status
reporter had been replaced by a failing executable and the status timer had
been stopped. The next service start restored the exact previous reporter from
the hash-validated rollback, removed the marker only after health recovery,
restarted the timer, completed the normal report successfully, and recorded
the attempted `1.4.1-dev` update as failed with rollback available. LOGIN01
received that result while continuing to report version `1.2.1` and all four
client health fields as `ok`. LightDM and the persistent VNC service remained
active throughout. MOBILE01 was explicitly excluded from this acceptance and
remains a separate future topic.

For a controlled full-client offline test, `scripts/test-client-offline-window.sh`
accepts an explicit NetworkManager interface and defaults to a 20-minute
window. It schedules and verifies a local systemd reconnect timer before it
disconnects the interface. If the timer cannot be armed, the script refuses to
change connectivity. Remote access is expected to disappear for the selected
window; the interface, route and normal status report must be checked again
after reconnection.

The full 20-minute offline window was accepted on WYSE01 on 20 October 2026.
During the window, LOGIN01 correctly treated the last report as stale and the
native greeter kept the normal username/password fallback selectable. The
reconnect timer restored `enp1s0`, its NetworkManager profile and the default
route without remote intervention. The transient timer then disappeared as
designed. LightDM, the native greeter, the client-status timer and persistent
VNC were active after recovery; the next status run succeeded and LOGIN01
again received all four health fields as `ok`. The observed delay before the
greeter becomes ready remains a separate user-interface design topic and does
not change the authentication fallback.

On 21 October 2026, the unified acceptance mode was itself accepted on WYSE01.
A temporary test key signed a package containing the exact already-installed
status reporter; no production or development release key was used or changed.
The command verified the signature, installed reporter hash and mode, exact
`1.4.1-dev` release/component binding, complete recovery rollback and service
health in one pass. The pre-check found that the manually created recovery-test
rollback directory was mode `0755`; acceptance was tightened to reject that
state and the directory was corrected to `0700` before the successful run.
LightDM, VNC, NetworkManager and the status timer remained active, LOGIN01
received a fresh report with all health fields `ok`, and no transaction marker
remained. The temporary package, public key and private test key were deleted.
The updater deployment can be reverted with
`/root/swbadge-client-acceptance-rollback-20261021T071757Z`.
