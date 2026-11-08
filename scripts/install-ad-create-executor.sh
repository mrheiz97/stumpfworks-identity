#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /path/to/linux/create-executor" >&2
    exit 2
fi
binary=$1
source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
unit=sw-badge-ad-create-executor.service
root=${DESTDIR:-}
case "$root" in
    '') [ "$(id -u)" -eq 0 ] || exit 1 ;;
    /*) [ -d "$root" ] || exit 1 ;;
    *) echo "DESTDIR must be an absolute staging directory" >&2; exit 2 ;;
esac
[ -f "$binary" ] && [ -x "$binary" ]

install -d "$root/opt/stumpfworks-badge" "$root/usr/lib/systemd/system"
install -m 0755 -- "$binary" "$root/opt/stumpfworks-badge/create-executor"
install -m 0644 -- "$source_dir/deploy/systemd/$unit" "$root/usr/lib/systemd/system/$unit"
install -m 0644 -- "$source_dir/deploy/systemd/sw-badge-ad-create-fixed.service" "$root/usr/lib/systemd/system/sw-badge-ad-create-fixed.service"
echo "Installed the executor and static units. Activation markers and state are provisioned separately."
