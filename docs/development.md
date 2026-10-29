# Development and Deployment

## Local verification

```bash
gofmt -w ./cmd ./internal
go test ./...
python3 -m py_compile cmd/native-greeter/sw-badge-native-greeter.py
python3 -m py_compile scripts/swbadge-sqlite-backup.py
python3 -m py_compile scripts/swbadge-postgres-backup.py
sh -n scripts/swbadge-cert-check.sh
git diff --check
```

The PKINIT test invokes OpenSSL. Run it on Linux when Windows lacks the CLI. Use disposable databases and caches locally. Never copy production secrets into the repository.

## Linux build

```bash
go build -trimpath -o bin/sw-badge-server ./cmd/server
sha256sum bin/sw-badge-server
```

For a Windows cross-build set `GOOS=linux`, `GOARCH=amd64` and `CGO_ENABLED=0`.

Before replacing a production binary, inspect the active unit, create a timestamped rollback, transfer to `/tmp`, verify the checksum, install atomically and restart only `sw-badge-server.service`. Verify health, UI and a real badge login.

## Greeter changes

1. Run `python3 -m py_compile`.
2. Inspect the active WYSE01 file and LightDM state.
3. Create a new rollback for the affected file.
4. Transfer and install only that file.
5. Restart LightDM and transient VNC if needed.
6. Verify process, logs, 1920×1080 layout, badge and password paths.

Do not remove the explicit screen-size correction without physical display testing.

## Discipline

- Preserve unrelated worktree changes.
- Never commit credential material.
- Keep DC01, PAM and Samba changes small and reversible.
- Change FILE01 only when explicitly authorized.
- Retest password fallback after authentication-stack changes.

## Deferred UI direction

The functional server, migrations, security boundaries, rollback procedures
and end-to-end tests take priority over another visual rewrite. After those
phases are complete, use the **shadcn Dashboard Template** as the preferred
visual reference for a cohesive redesign of the administration and
self-service web interface. Start with a local concept and component inventory;
do not assume that adopting its React implementation is required. The final
choice must preserve server-side authorization, CSRF protection, secret-free
browser state, accessibility, maintainability and the existing interface as a
tested rollback.
