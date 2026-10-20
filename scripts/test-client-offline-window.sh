#!/bin/sh
set -eu

usage() {
    echo "usage: $0 <network-interface> [duration]" >&2
    echo "example: $0 enp1s0 20m" >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage

interface=$1
duration=${2:-20m}

case "$interface" in
    *[!A-Za-z0-9_.:-]*|'')
        echo "invalid network interface" >&2
        exit 2
        ;;
esac

case "$duration" in
    *[smh]) duration_value=${duration%?} ;;
    *) duration_value= ;;
esac
case "$duration_value" in
    ''|*[!0-9]*)
        echo "duration must use syntax such as 30s, 20m or 1h" >&2
        exit 2
        ;;
esac
[ "$duration_value" -gt 0 ] || {
    echo "duration must be greater than zero" >&2
    exit 2
}

if [ "$(id -u)" -ne 0 ]; then
    echo "this test must run as root" >&2
    exit 1
fi

for command in nmcli systemctl systemd-run; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required command is unavailable: $command" >&2
        exit 1
    }
done

systemctl is-active --quiet NetworkManager.service || {
    echo "NetworkManager is not active" >&2
    exit 1
}

state=$(nmcli -g GENERAL.STATE device show "$interface" 2>/dev/null || true)
case "$state" in
    100\ *|'100 (connected)') ;;
    *)
        echo "interface $interface is not connected" >&2
        exit 1
        ;;
esac

unit="swbadge-network-reconnect-$(date -u +%Y%m%dT%H%M%SZ)"
systemd-run \
    --quiet \
    --collect \
    --unit "$unit" \
    --on-active "$duration" \
    /usr/bin/nmcli device connect "$interface"

timer_state=$(systemctl show "$unit.timer" --property=ActiveState --value)
if [ "$timer_state" != "active" ]; then
    echo "reconnect timer was not activated; refusing to disconnect" >&2
    exit 1
fi

echo "Reconnect timer active: $unit.timer ($duration)"
echo "Disconnecting $interface; remote access will be unavailable."
nmcli device disconnect "$interface"
