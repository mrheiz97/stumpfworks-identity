# Disposable, synthetic-only verification. No production endpoints or data.
$ErrorActionPreference = 'Stop'
$pgBin = 'C:\Program Files\PostgreSQL\17\bin'
$taskCluster = Join-Path ([System.IO.Path]::GetTempPath()) ('identity-update-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskCluster | Out-Null
$taskStarted = $false
try {
    & (Join-Path $pgBin 'initdb.exe') -D $taskCluster -U postgres -A trust --encoding=UTF8 --no-locale
    if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL initialization failed' }
    & (Join-Path $pgBin 'pg_ctl.exe') -D $taskCluster -l (Join-Path $taskCluster 'server.log') -o '-h 127.0.0.1 -p 55441' -w start
    if ($LASTEXITCODE -ne 0) { throw 'Disposable PostgreSQL startup failed' }
    $taskStarted = $true
    $env:IDENTITY_TEST_POSTGRES_URL = 'postgres://postgres@127.0.0.1:55441/postgres?sslmode=disable'
    $env:IDENTITY_TEST_PG_DUMP = Join-Path $pgBin 'pg_dump.exe'
    $env:IDENTITY_TEST_PG_RESTORE = Join-Path $pgBin 'pg_restore.exe'
    $env:PATH = 'C:\Program Files\Git\usr\bin;' + $env:PATH
    # Each cluster is new: do not reuse cached integration-test results from
    # another disposable instance with the same connection URL.
    go test -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw 'Verification failed' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go vet failed' }
}
finally {
    if ($taskStarted) {
        & (Join-Path $pgBin 'pg_ctl.exe') -D $taskCluster -m fast -w stop
    }
    # Retain the stopped synthetic cluster for inspection; print its exact
    # location. Cleanup is a separate, validated local operation.
    Write-Output ('Stopped synthetic test cluster: ' + $taskCluster)
}
