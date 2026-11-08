#!/bin/sh
# Only for the disposable postgres:17-alpine container, --network none, no ports.
set -eu
mkdir -p /tmp/identity-pg
chown postgres:postgres /tmp/identity-pg
gosu postgres initdb -D /tmp/identity-pg -U postgres -A trust --encoding=UTF8 --no-locale >/tmp/initdb.log
gosu postgres pg_ctl -D /tmp/identity-pg -l /tmp/identity-pg.log -o '-h 127.0.0.1 -p 55441' -w start
trap 'gosu postgres pg_ctl -D /tmp/identity-pg -m fast -w stop' EXIT
export IDENTITY_TEST_POSTGRES_URL='postgres://postgres@127.0.0.1:55441/postgres?sslmode=disable'
/workspace/adprofile.test -test.v -test.run Postgres
